"""Checkpointed causal temporal GRU baseline on observed controlled gateway requests.

This is a lab engineering baseline, NOT a graph neural network and NOT real intrusion evidence.
Never trains on held-out test episodes or on post-milestone windows.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path

import numpy as np
import torch
from torch import nn
from torch.nn.utils.rnn import pad_sequence,pack_padded_sequence
from src.code.ingest import load_manifest,load_events
from src.code.features import FEATURE_COLUMNS, make_windows
from src.code.pipeline import split_episode_ids,choose_validation_threshold,episode_detection_metrics
from src.code.early_warning import early_warning_metrics


class GRUDetector(nn.Module):
    def __init__(self, dim:int, hidden:int=32):
        super().__init__()
        self.gru=nn.GRU(dim,hidden,batch_first=True)
        self.head=nn.Linear(hidden,1)
    def forward(self,x,lengths):
        packed=pack_padded_sequence(x,lengths.cpu(),batch_first=True,enforce_sorted=False)
        _,last=self.gru(packed)
        return self.head(last[-1]).flatten()


def examples(rows,mean,std,sequence_length=6):
    grouped=defaultdict(list)
    for row in rows: grouped[row['episode_id']].append(row)
    out=[]
    for eid,group in grouped.items():
        group.sort(key=lambda r:r['window_end_ts'])
        matrix=np.asarray([[r[c] for c in FEATURE_COLUMNS] for r in group],dtype=np.float32)
        matrix=((matrix-mean)/std).astype(np.float32)
        if not np.isfinite(matrix).all():raise ValueError('Nonfinite features after scaling')
        for i,row in enumerate(group):
            seq=matrix[max(0,i-sequence_length+1):i+1]
            out.append({'x':torch.from_numpy(seq.copy()),'y':int(row['label']),'episode_id':eid,'ts':float(row['window_end_ts'])})
    return out


def batches(items,batch_size:int,seed:int,shuffle:bool):
    rng=np.random.default_rng(seed)
    order=rng.permutation(len(items)) if shuffle else np.arange(len(items))
    for start in range(0,len(order),batch_size):
        chunk=[items[int(i)] for i in order[start:start+batch_size]]
        xx=pad_sequence([e['x'] for e in chunk],batch_first=True,padding_value=0.0)
        lengths=torch.tensor([e['x'].shape[0] for e in chunk],dtype=torch.int64)
        yy=torch.tensor([e['y'] for e in chunk],dtype=torch.float32)
        yield xx,lengths,yy,chunk


def inference(model,rows,device,batch_size=128):
    model.eval(); preds=[]
    with torch.inference_mode():
        for xx,lengths,_,chunk in batches(rows,batch_size,0,False):
            scores=torch.sigmoid(model(xx.to(device),lengths)).cpu().tolist()
            preds.extend({'episode_id':e['episode_id'],'window_end_ts':e['ts'],
                          'score':float(s),'label':e['y']} for e,s in zip(chunk,scores))
    return preds


def _atomic_torch_save(path,record):
    temp=path.with_name(path.name+'.pending')
    if temp.exists():raise FileExistsError(f'Existing pending checkpoint: {temp}')
    torch.save(record,temp);temp.replace(path)


def train_policy(policy,manifest,windows,all_windows,out_dir,device,epochs,seed):
    out_dir.mkdir(parents=True,exist_ok=True)
    final=out_dir/'complete.json'; ckpt=out_dir/'latest.pt'
    if final.exists():
        print(policy,': already complete; not overwriting',flush=True);return
    tr_ids,va_ids=split_episode_ids(manifest,policy,seed)
    test_ids={eid for eid,v in manifest.items() if v['policy']=='test'}
    train=[r for r in windows if r['episode_id'] in tr_ids]
    valid=[r for r in windows if r['episode_id'] in va_ids]
    test=[r for r in all_windows if r['episode_id'] in test_ids]
    if not train or not valid or not test:raise ValueError('Insufficient train/val/test windows')
    train_matrix=np.asarray([[r[c] for c in FEATURE_COLUMNS] for r in train],dtype=np.float32)
    if not np.isfinite(train_matrix).all():raise ValueError('Nonfinite features')
    mean=train_matrix.mean(axis=0);std=train_matrix.std(axis=0)
    std=np.where(std<1e-6,1.0,std).astype(np.float32)
    tr=examples(train,mean,std);va=examples(valid,mean,std);te=examples(test,mean,std)
    torch.manual_seed(seed)
    if torch.cuda.is_available():torch.cuda.manual_seed_all(seed)
    model=GRUDetector(len(FEATURE_COLUMNS),hidden=32).to(device)
    optimiser=torch.optim.AdamW(model.parameters(),lr=0.001,weight_decay=0.001)
    criterion=nn.BCEWithLogitsLoss()
    first_epoch=1
    if ckpt.exists():
        saved=torch.load(ckpt,map_location='cpu',weights_only=True)
        if saved['policy']!=policy or saved['seed']!=seed or saved['feature_columns']!=list(FEATURE_COLUMNS):
            raise ValueError('Checkpoint config does not match request; refusing unsafe resume')
        if saved['mean']!=mean.tolist() or saved['std']!=std.tolist():
            raise ValueError('Input distribution changed since checkpoint; refusing resume')
        model.load_state_dict(saved['model_state']);optimiser.load_state_dict(saved['optimizer_state'])
        torch.set_rng_state(saved['torch_rng'])
        if device.type=='cuda' and saved['cuda_rng'] is not None:torch.cuda.set_rng_state_all(saved['cuda_rng'])
        first_epoch=saved['epoch']+1
        print(policy,': restoring checkpoint at epoch',saved['epoch'],flush=True)
    for epoch in range(first_epoch,epochs+1):
        model.train();losses=[]
        for xx,lengths,yy,_ in batches(tr,32,seed+epoch,True):
            xx=xx.to(device);yy=yy.to(device)
            optimiser.zero_grad(set_to_none=True)
            loss=criterion(model(xx,lengths),yy)
            if not torch.isfinite(loss):raise ValueError('Nonfinite loss')
            loss.backward();nn.utils.clip_grad_norm_(model.parameters(),1.0);optimiser.step()
            losses.append(float(loss.item()))
        checkpoint={'policy':policy,'seed':seed,'epoch':epoch,'model_state':model.state_dict(),
                    'optimizer_state':optimiser.state_dict(),'feature_columns':list(FEATURE_COLUMNS),
                    'mean':mean.tolist(),'std':std.tolist(),'torch_rng':torch.get_rng_state(),
                    'cuda_rng':torch.cuda.get_rng_state_all() if device.type=='cuda' else None}
        _atomic_torch_save(ckpt,checkpoint)
        with (out_dir/'epochs.jsonl').open('a',encoding='utf8') as f:
            f.write(json.dumps({'epoch':epoch,'train_bce':sum(losses)/len(losses)})+'\n')
        if epoch==1 or epoch%10==0 or epoch==epochs:
            print(policy,'epoch',epoch,'train BCE',round(sum(losses)/len(losses),4),flush=True)
    if first_epoch>epochs and not ckpt.exists():raise ValueError('No checkpoint to evaluate')
    val_pred=inference(model,va,device)
    val_man={eid:manifest[eid] for eid in va_ids}
    threshold=choose_validation_threshold(val_pred,val_man)
    preds=inference(model,te,device)
    test_man={eid:manifest[eid] for eid in test_ids}
    result={'policy':policy,'seed':seed,'epochs':epochs,'device':str(device),
            'samples':{'train':len(tr),'val':len(va),'held_out':len(te)},
            'threshold_validation_only':threshold,'status':'LAB_TRAFFIC_ENGINEERING_BASELINE_NOT_CYBERSECURITY_EVIDENCE'}
    if threshold is None:
        result['warning']='No validation threshold meets constrained false positive episode rate; no test metrics at a chosen threshold'
    else:
        result['detection']=episode_detection_metrics(preds,test_man,threshold)
        w=early_warning_metrics(preds,test_man,threshold)
        result['early_warning']={k:v for k,v in w.items() if k!='episode_results'}
        result['per_episode']=w['episode_results']
    tmp=final.with_suffix('.pending')
    tmp.write_text(json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')
    tmp.replace(final)
    print(policy,'finished; output',final,flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--epochs',type=int,default=60);p.add_argument('--device',choices=['auto','cuda','cpu'],default='auto')
    p.add_argument('--seed',type=int,default=20261112);args=p.parse_args()
    if args.epochs<1 or args.epochs>500:p.error('epochs 1..500')
    torch.set_num_threads(2)
    device=torch.device('cuda' if args.device=='auto' and torch.cuda.is_available() else ('cpu' if args.device=='auto' else args.device))
    if device.type=='cuda' and not torch.cuda.is_available():raise RuntimeError('CUDA requested but not available')
    raw=Path('src/data/raw/runs')/args.run
    manifest=load_manifest(raw/'episodes.jsonl')
    observations=load_events(raw/'gateway_subset.jsonl',manifest,source='gateway')
    train_windows=make_windows(observations,manifest,n_events=4,min_events=3,before_milestone_only=True)
    all_windows=make_windows(observations,manifest,n_events=4,min_events=3,before_milestone_only=False)
    print('GPU temporal baseline:',device, 'episodes',len(manifest),'training windows',len(train_windows),flush=True)
    for policy in ('fixed','random','strategic'):
        train_policy(policy,manifest,train_windows,all_windows,args.output/policy,device,args.epochs,args.seed)
    print('GRU_FINISHED')
if __name__=='__main__':main()
