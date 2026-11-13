"""Extract ONLY a specified, completed pilot run from a persistent gateway log.

Does not relabel or fabricate observations. Does not modify the raw gateway log.
"""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path
from src.code.ingest import load_manifest, load_events


def extract(manifest_path: Path, gateway_path: Path, output_path: Path) -> dict:
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite: {output_path}")
    manifest = load_manifest(manifest_path)
    ids = set(manifest)
    records = []
    with gateway_path.open(encoding="utf-8") as src:
        for lineno, line in enumerate(src, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid shared gateway log line {lineno}") from exc
            if row.get("episode_id") in ids:
                records.append(row)
    if not records:
        raise ValueError("No matching gateway events; do not produce a dataset")
    count = Counter(r['episode_id'] for r in records)
    expected = {eid: int(manifest[eid].get('requests', -1)) for eid in ids}
    bad = {eid: (count[eid], n) for eid, n in expected.items() if count[eid] != n or n <= 0}
    if bad:
        raise ValueError(f"Incomplete or duplicated pilot episode counts (observed, expected): {bad}")
    for row in records:
        if int(row.get('status', -1)) != 200:
            raise ValueError("Non-200 HTTP response in selected pilot run")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Only completed, validated observed records are published as a run-specific dataset.
    temp = output_path.with_suffix(output_path.suffix + '.pending')
    if temp.exists():
        raise FileExistsError(f"Pending output exists: {temp}")
    try:
        with temp.open('x', encoding='utf-8') as dst:
            for row in records:
                dst.write(json.dumps(row, sort_keys=True) + '\n')
        verified = load_events(temp, manifest, source='gateway')
        if len(verified) != len(records):
            raise ValueError("Episode/time validation dropped events")
        temp.rename(output_path)
    finally:
        if temp.exists():
            temp.unlink()
    return {'status':'validated_observed_gateway_subset_not_real_attack_data',
            'episodes':len(manifest), 'events':len(records), 'output':str(output_path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--gateway', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(extract(args.manifest, args.gateway, args.out), indent=2))

if __name__ == '__main__':
    main()
