"""Independent, persistent CPU HPO on a completed LAB-GATEWAY run.

No held-out test observations may enter fitting, validation or tuning.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import optuna
from src.code.ingest import load_manifest,load_events
from src.code.features import make_windows
from src.code.pipeline import split_episode_ids
from src.code.models import tune_forest


def hpo(run_id:str,output:Path,trials:int,seed:int):
    raw=Path('src/data/raw/runs')/run_id
    manifest=load_manifest(raw/'episodes.jsonl')
    events=load_events(raw/'gateway_subset.jsonl',manifest,source='gateway')
    windows=make_windows(events,manifest,n_events=4,min_events=3,before_milestone_only=True)
    output.mkdir(parents=True,exist_ok=True)
    for policy in ('fixed','random','strategic'):
        train,val=split_episode_ids(manifest,policy,seed)
        tr=[r for r in windows if r['episode_id'] in train];va=[r for r in windows if r['episode_id'] in val]
        db=output/f'{policy}.sqlite3'
        best=tune_forest(tr,va,seed=seed,trials=trials,db_path=db,study_name=f'phase3_{run_id}_{policy}_rf')
        storage=f'sqlite:///{db.resolve()}'
        study=optuna.load_study(study_name=f'phase3_{run_id}_{policy}_rf',storage=storage)
        report={'run_id':run_id,'policy':policy,'best_params':best,'best_validation_pr_auc':float(study.best_value),
                'finished_trials':sum(t.state.name=='COMPLETE' for t in study.trials),'study_db':str(db.resolve()),
                'note':'Validation-only tuning on tiny controlled lab data, NOT a claimed real-intrusion result'}
        dest=output/f'{policy}_best.json';tmp=dest.with_suffix('.pending')
        tmp.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');tmp.replace(dest)
        print(policy,'complete:',report,flush=True)
    print('HPO_FINISHED')

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--trials',type=int,default=30,help='ADDITIONAL trials per policy each execution')
    p.add_argument('--seed',type=int,default=20261112);args=p.parse_args()
    if not 1<=args.trials<=500: p.error('1..500 trials required')
    hpo(args.run,args.output,args.trials,args.seed)
if __name__=='__main__':main()
