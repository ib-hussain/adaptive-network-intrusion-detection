"""Read-only audit of an existing real PCAP + independently recorded lab manifest.

Reprocesses packet trace through Zeek -C in a NEW directory. Never changes raw data.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
from src.code.ingest import load_manifest, read_jsonl


def sha256(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()


def inspect_pcap(path):
    # Classic pcap only. Retain warning if pcapng or unusual capture encapsulation.
    with open(path,'rb') as f:
        magic=f.read(4)
        if magic in [bytes.fromhex('d4c3b2a1'),bytes.fromhex('4d3cb2a1')]:en='<'
        elif magic in [bytes.fromhex('a1b2c3d4'),bytes.fromhex('a1b23c4d')]:en='>'
        else:return {'supported':False,'magic_hex':magic.hex(),'reason':'Only classic PCAP supported by this inspector'}
        hdr=f.read(20)
        if len(hdr)!=20:raise ValueError('Truncated PCAP global header')
        _,_,_,_,snaplen,linktype=struct.unpack(en+'HHIIII',hdr)
        count=0; nontrivial=0; bytecount=0; malformed=0
        while True:
            frame=f.read(16)
            if not frame:break
            if len(frame)!=16:malformed+=1;break
            _,_,captured,original=struct.unpack(en+'IIII',frame)
            if captured>snaplen or captured>10_000_000:malformed+=1;break
            data=f.read(captured)
            if len(data)!=captured:malformed+=1;break
            count+=1;bytecount+=captured;nontrivial+=int(captured>100)
        return {'supported':True,'frames':count,'frames_over_100_bytes':nontrivial,'captured_bytes':bytecount,'malformed_frames':malformed,'linktype':linktype,'snaplen':snaplen}


def audit(repo:Path,run_id:str,output_dir:Path):
    raw=repo/'src/data/raw/runs'/run_id
    manifest_path=raw/'episodes.jsonl'; pcap=raw/'traffic.pcap'
    if not manifest_path.is_file() or not pcap.is_file(): raise FileNotFoundError('Expected both manifest and PCAP in '+str(raw))
    output_dir.mkdir(parents=True,exist_ok=False)
    manifest=load_manifest(manifest_path)
    stats={'run_id':run_id,'manifest_count':len(manifest),'policy_counts':dict(Counter(e['policy'] for e in manifest.values())),
           'condition_counts':dict(Counter(e['condition'] for e in manifest.values())),
           'pcap_bytes_on_disk':pcap.stat().st_size,'pcap_sha256':sha256(pcap),'manifest_sha256':sha256(manifest_path),
           'pcap':inspect_pcap(pcap),'raw_gateway_subset_present':(raw/'gateway_subset.jsonl').is_file(),
           'classification':'LAB_NETWORK_TELEMETRY_DIAGNOSTIC_ONLY'}
    subset=raw/'gateway_subset.jsonl'
    if subset.is_file():
        events=read_jsonl(subset); counts=Counter(e.get('episode_id') for e in events)
        stats['gateway_events']=len(events)
        stats['gateway_episode_count_matches'] = all(counts[eid]==int(ep.get('requests',-1)) for eid,ep in manifest.items())
        stats['gateway_http_codes']=dict(Counter(str(e.get('status')) for e in events))
    zeekout=output_dir/'zeek_checksums_ignored';zeekout.mkdir()
    try:
        proc=subprocess.run(['zeek','-C','-r',str(pcap.resolve()),'LogAscii::use_json=T'],cwd=zeekout,timeout=240,capture_output=True,text=True)
        stats['zeek_returncode']=proc.returncode
        stats['zeek_stderr_tail']=proc.stderr[-2500:]
        conn=zeekout/'conn.log'
        if conn.is_file() and conn.stat().st_size:
            records=read_jsonl(conn)
            stats['zeek_conn_records']=len(records)
            stats['zeek_positive_orig_bytes']=sum(float(r.get('orig_bytes') or 0)>0 for r in records)
            stats['zeek_positive_resp_bytes']=sum(float(r.get('resp_bytes') or 0)>0 for r in records)
            counts=Counter()
            unaligned=0;ambiguous=0
            episodes=sorted(manifest.values(),key=lambda e:e['start_ts'])
            for record in records:
                ts=float(record.get('ts',-1))
                matches=[e for e in episodes if float(e['start_ts'])<=ts<=float(e['end_ts'])]
                if len(matches)==1:counts[matches[0]['episode_id']]+=1
                elif not matches:unaligned+=1
                else:ambiguous+=1
            stats['zeek_episodes_with_conn']=len(counts)
            stats['zeek_unaligned_conn']=unaligned
            stats['zeek_ambiguous_conn']=ambiguous
            stats['zeek_conn_coverage_fraction']=len(counts)/len(manifest)
            stats['zeek_conn_per_episode_summary']={'min':min(counts.values()) if counts else 0,'max':max(counts.values()) if counts else 0}
        else:stats['zeek_conn_records']=0
    except (FileNotFoundError,subprocess.TimeoutExpired) as exc:
        stats['zeek_error']=str(exc)
    stats['warning']='Zeek connections can differ from gateway events: gateway -> server PCAP capture has distinct semantics. Inspect both directions and application payload independently.'
    report=output_dir/'audit.json'
    report.write_text(json.dumps(stats,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')
    return report


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',required=True);p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();path=audit(Path.cwd(),args.run,args.output)
    print('Audit saved:',path)
    print(path.read_text())
if __name__=='__main__':main()
