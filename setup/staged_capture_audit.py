"""Validate classic tcpdump PCAP packet records. Never infer capture from file size alone.

Does not change the input file. A 24-byte header-only PCAP is invalid.
This is a structural integrity check, not independent network-ground-truth verification.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct

# magic bytes -> endian. Classic pcap only; tcpdump -w emits this by default.
MAGICS = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
          b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}


def inspect_pcap(path: Path) -> dict:
    p = Path(path)
    out = {"path": str(p), "size_bytes": p.stat().st_size if p.is_file() else 0,
           "packets": 0, "payload_bytes": 0, "complete": False, "issue": None}
    if not p.is_file():
        out['issue'] = 'PCAP does not exist'
        return out
    with p.open('rb') as f:
        header = f.read(24)
        if len(header) != 24:
            out['issue'] = 'Missing or incomplete 24-byte PCAP header'
            return out
        endian = MAGICS.get(header[:4])
        if endian is None:
            out['issue'] = 'Unsupported PCAP format or invalid magic (pcapng is not classic pcap)'
            return out
        out['version'] = list(struct.unpack(endian + 'HH', header[4:8]))
        out['linktype'] = struct.unpack(endian + 'I', header[20:24])[0]
        if out['version'] != [2, 4]:
            out['issue'] = 'Unsupported PCAP version'
            return out
        while True:
            record = f.read(16)
            if not record:
                out['complete'] = True
                break
            if len(record) != 16:
                out['issue'] = 'Truncated per-packet header'
                break
            _sec, _fraction, caplen, origlen = struct.unpack(endian + 'IIII', record)
            if caplen <= 0 or caplen > 16 * 1024 * 1024 or origlen < caplen:
                out['issue'] = 'Implausible captured/original packet length'
                break
            if len(f.read(caplen)) != caplen:
                out['issue'] = 'Truncated packet data (capture may still be active)'
                break
            out['packets'] += 1
            out['payload_bytes'] += caplen
    if out['complete'] and out['packets'] == 0:
        out['issue'] = 'Header-only PCAP: zero packet records; no network evidence'
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pcap', required=True, type=Path)
    parser.add_argument('--min-packets', type=int, default=1)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args()
    if args.min_packets < 1:
        parser.error('min-packets must be positive')
    report = inspect_pcap(args.pcap)
    report['min_packets'] = args.min_packets
    report['valid'] = report['complete'] and report['packets'] >= args.min_packets
    if not report['valid'] and not report['issue']:
        report['issue'] = f"Only {report['packets']} packet records; minimum {args.min_packets}"
    if args.output:
        if args.output.exists():
            raise FileExistsError(f'Will not overwrite existing audit: {args.output}')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    if not args.quiet or not report['valid']:
        print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['valid'] else 2)


if __name__ == '__main__':
    main()
