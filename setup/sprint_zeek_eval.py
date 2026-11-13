"""Evaluate archived Zeek -C network flows ONLY if the sensor audit passes conservative gates.

Distinct from application gateway observations; never merges or reuses their features.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from src.code.ingest import load_manifest,load_events
from src.code.features import make_windows
from src.code.pipeline import run_pipeline


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--run',required=True);p.add_argument('--audit',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    report=json.loads((a.audit/'audit.json').read_text())
    if report.get('zeek_returncode') != 0 or report.get('zeek_conn_coverage_fraction',0)<0.8 or report.get('zeek_ambiguous_conn',1):
        raise SystemExit('ZEEK_MODEL_NOT_RUN: insufficient trustworthy network-flow coverage or an ambiguous timestamp join; inspect audit.json')
    if report.get('zeek_positive_orig_bytes',0)==0 or report.get('zeek_positive_resp_bytes',0)==0:
        raise SystemExit('ZEEK_MODEL_NOT_RUN: no positive orig/resp byte counters; inspect checksum/capture visibility first')
    raw=Path('src/data/raw/runs')/a.run
    manifest_path=raw/'episodes.jsonl'
    conn=a.audit/'zeek_checksums_ignored'/'conn.log'
    manifest=load_manifest(manifest_path)
    events=load_events(conn,manifest,source='zeek')
    windows=make_windows(events,manifest,n_events=4,min_events=3,before_milestone_only=True)
    observed={w['episode_id'] for w in windows}
    if any(eid not in observed for eid,e in manifest.items() if e['policy']=='test'):
        raise SystemExit('ZEEK_MODEL_NOT_RUN: held-out test episodes missing sufficient Zeek windows; inspect capture coverage')
    result=run_pipeline(manifest_path,conn,a.output,source='zeek',trials=0)
    print('ZEEK_NETWORK_BASELINE_COMPLETE:',a.output,'episodes',result['n_episodes'],'events',result['n_events'])
if __name__=='__main__':main()
