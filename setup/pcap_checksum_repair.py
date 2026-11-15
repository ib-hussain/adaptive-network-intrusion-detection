"""Recompute IPv4/TCP/UDP checksums in a classic pcap into a derived copy.

The raw capture is never modified. This addresses a known artefact of the
isolated Docker lab: the veth pair leaves TCP/UDP checksums in the
CHECKSUM_PARTIAL state (NIC transmit offloading), so a strict Zeek reader
discards the payload of every data segment and reports zero byte counters.

The repair only rewrites the checksum fields. Every other byte of every packet
is copied verbatim, and the tool proves it by comparing the two buffers and
reporting exactly which byte offsets changed.

Reference behaviour matches ``tcprewrite --fixcsum``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGICS = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
          b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def checksum16(data: bytes) -> int:
    return (~_ones_complement_sum(data)) & 0xFFFF


def _network_offset(linktype: int, frame: bytes) -> int | None:
    """Byte offset of the network layer inside a captured frame."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8) and len(frame) >= offset + 4:
            ethertype = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        return offset if ethertype == 0x0800 else None
    if linktype == LINKTYPE_RAW:
        return 0
    if linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        protocol = struct.unpack("!H", frame[14:16])[0]
        return 16 if protocol == 0x0800 else None
    if linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        protocol = struct.unpack("!H", frame[0:2])[0]
        return 20 if protocol == 0x0800 else None
    return None


def repair_frame(linktype: int, frame: bytes) -> tuple[bytes, set[int]]:
    """Return (repaired_frame, changed_byte_offsets) for one captured frame."""
    off = _network_offset(linktype, frame)
    if off is None:
        return frame, set()
    if len(frame) < off + 20:
        return frame, set()
    version_ihl = frame[off]
    if (version_ihl >> 4) != 4:
        return frame, set()
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < off + ihl:
        return frame, set()
    total_length = struct.unpack("!H", frame[off + 2:off + 4])[0]
    if total_length < ihl or len(frame) < off + total_length:
        total_length = len(frame) - off
    proto = frame[off + 9]
    mutable = bytearray(frame)
    checksum_offsets: set[int] = set()

    # IPv4 header checksum.
    ip_header = bytearray(mutable[off:off + ihl])
    ip_header[10] = 0
    ip_header[11] = 0
    new_ip = checksum16(bytes(ip_header))
    if struct.unpack("!H", mutable[off + 10:off + 12])[0] != new_ip:
        mutable[off + 10:off + 12] = struct.pack("!H", new_ip)
    checksum_offsets.update({off + 10, off + 11})

    l4 = off + ihl
    if proto == 6 and len(mutable) >= l4 + 20:
        data_offset = (mutable[l4 + 12] >> 4) * 4
        if 20 <= data_offset and len(mutable) >= l4 + data_offset:
            segment = bytearray(mutable[l4:l4 + total_length - ihl])
            if len(segment) >= data_offset:
                segment[16] = 0
                segment[17] = 0
                pseudo = mutable[off + 12:off + 20] + b"\x00" + bytes([proto]) + struct.pack("!H", len(segment))
                new_tcp = checksum16(bytes(pseudo) + bytes(segment))
                if struct.unpack("!H", mutable[l4 + 16:l4 + 18])[0] != new_tcp:
                    mutable[l4 + 16:l4 + 18] = struct.pack("!H", new_tcp)
                checksum_offsets.update({l4 + 16, l4 + 17})
    elif proto == 17 and len(mutable) >= l4 + 8:
        udp_length = struct.unpack("!H", mutable[l4 + 4:l4 + 6])[0]
        if udp_length >= 8 and len(mutable) >= l4 + udp_length:
            segment = bytearray(mutable[l4:l4 + udp_length])
            segment[6] = 0
            segment[7] = 0
            pseudo = mutable[off + 12:off + 20] + b"\x00" + bytes([proto]) + struct.pack("!H", len(segment))
            new_udp = checksum16(bytes(pseudo) + bytes(segment))
            if new_udp == 0:
                new_udp = 0xFFFF
            if struct.unpack("!H", mutable[l4 + 6:l4 + 8])[0] != new_udp:
                mutable[l4 + 6:l4 + 8] = struct.pack("!H", new_udp)
            checksum_offsets.update({l4 + 6, l4 + 7})
    changed = {i for i in checksum_offsets if frame[i] != mutable[i]}
    return bytes(mutable), changed


def repair_pcap(source: Path, destination: Path) -> dict:
    source, destination = Path(source), Path(destination)
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite: {destination}")
    with source.open("rb") as fp:
        header = fp.read(24)
        if len(header) != 24:
            raise ValueError("Truncated pcap global header")
        endian = MAGICS.get(header[:4])
        if endian is None:
            raise ValueError("Unsupported pcap format (classic pcap only)")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        packets = 0
        frames_with_change = 0
        bytes_changed = 0
        payload_bytes = 0
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_name(destination.name + ".pending")
        with tmp.open("xb") as out:
            out.write(header)
            while True:
                record = fp.read(16)
                if not record:
                    break
                if len(record) != 16:
                    raise ValueError("Truncated per-packet header")
                ts_sec, ts_usec, caplen, origlen = struct.unpack(endian + "IIII", record)
                data = fp.read(caplen)
                if len(data) != caplen:
                    raise ValueError("Truncated packet data")
                repaired, changed = repair_frame(linktype, data)
                if changed:
                    frames_with_change += 1
                    bytes_changed += len(changed)
                    # Prove that only checksum fields changed.
                    if len(repaired) != len(data):
                        raise AssertionError("Repair changed the packet length")
                    differing = {i for i in range(len(data)) if data[i] != repaired[i]}
                    if differing != changed:
                        raise AssertionError("Repair changed bytes outside the checksum fields")
                packets += 1
                payload_bytes += caplen
                out.write(record)
                out.write(repaired)
        tmp.replace(destination)
    return {
        "source": str(source),
        "source_sha256": sha256(source),
        "output": str(destination),
        "output_sha256": sha256(destination),
        "linktype": linktype,
        "packets": packets,
        "frames_with_changed_checksums": frames_with_change,
        "checksum_bytes_changed": bytes_changed,
        "captured_bytes": payload_bytes,
        "tool": "setup/pcap_checksum_repair.py",
        "note": "Only IPv4 header / TCP / UDP checksum fields were rewritten; all other bytes copied verbatim.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    report = repair_pcap(args.pcap, args.output)
    if args.report:
        if args.report.exists():
            raise FileExistsError(f"Refusing to overwrite: {args.report}")
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
