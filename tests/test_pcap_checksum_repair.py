"""Regression tests for the pcap checksum-repair utility.

The repair must be provably minimal: only checksum fields may change.
"""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from setup import pcap_checksum_repair as repair


def _ethernet_ipv4_tcp_frame(payload: bytes = b"hello", bad_tcp_checksum: bool = True,
                             bad_ip_checksum: bool = False) -> bytes:
    src = bytes([172, 19, 0, 4])
    dst = bytes([172, 19, 0, 3])
    tcp = bytearray()
    tcp += struct.pack("!HH", 46528, 8080)
    tcp += struct.pack("!II", 1000, 2000)
    tcp += struct.pack("!BBH", 5 << 4, 0x18, 8192)
    tcp += struct.pack("!HH", 0, 0)          # checksum placeholder, urgent pointer
    tcp += payload
    pseudo = src + dst + b"\x00" + bytes([6]) + struct.pack("!H", len(tcp))
    correct = repair.checksum16(pseudo + bytes(tcp))
    if bad_tcp_checksum:
        struct.pack_into("!H", tcp, 16, (~correct) & 0xFFFF)
    else:
        struct.pack_into("!H", tcp, 16, correct)

    total_length = 20 + len(tcp)
    ip = bytearray()
    ip += bytes([0x45, 0x00])
    ip += struct.pack("!H", total_length)
    ip += struct.pack("!H", 0x1234)
    ip += struct.pack("!H", 0x4000)
    ip += bytes([64, 6, 0, 0])
    ip += src + dst
    correct_ip = repair.checksum16(bytes(ip))
    if bad_ip_checksum:
        struct.pack_into("!H", ip, 10, (~correct_ip) & 0xFFFF)
    else:
        struct.pack_into("!H", ip, 10, correct_ip)

    eth = bytes([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2]) + struct.pack("!H", 0x0800)
    return eth + bytes(ip) + bytes(tcp)


def _write_pcap(path: Path, frames: list[bytes]) -> Path:
    body = b""
    for i, frame in enumerate(frames):
        body += struct.pack("<IIII", 1700000000 + i, 0, len(frame), len(frame)) + frame
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + body)
    return path


def test_checksum16_matches_known_value():
    # RFC 1071 style check: the complement of the sum of a header is zero.
    assert repair.checksum16(b"\x00\x00") == 0xFFFF


def test_repair_fixes_tcp_checksum_and_changes_only_two_bytes():
    frame = _ethernet_ipv4_tcp_frame(bad_tcp_checksum=True)
    fixed, changed = repair.repair_frame(repair.LINKTYPE_ETHERNET, frame)
    assert len(changed) == 2
    assert {frame[i] for i in changed} != {fixed[i] for i in changed}
    # Everything outside the checksum field must be identical.
    for i in range(len(frame)):
        if i not in changed:
            assert frame[i] == fixed[i]


def test_repair_is_idempotent():
    frame = _ethernet_ipv4_tcp_frame(bad_tcp_checksum=True)
    once, _ = repair.repair_frame(repair.LINKTYPE_ETHERNET, frame)
    twice, changed = repair.repair_frame(repair.LINKTYPE_ETHERNET, once)
    assert changed == set()
    assert once == twice


def test_repair_fixes_ip_header_checksum_too():
    frame = _ethernet_ipv4_tcp_frame(bad_tcp_checksum=False, bad_ip_checksum=True)
    fixed, changed = repair.repair_frame(repair.LINKTYPE_ETHERNET, frame)
    # The Ethernet header is 14 bytes, so the IPv4 checksum field sits at 24/25.
    assert changed == {24, 25}
    assert repair.checksum16(fixed[14:34]) == 0


def test_repair_pcap_preserves_framing_and_counts(tmp_path):
    frames = [_ethernet_ipv4_tcp_frame(bad_tcp_checksum=True) for _ in range(5)]
    src = _write_pcap(tmp_path / "raw.pcap", frames)
    report = repair.repair_pcap(src, tmp_path / "fixed.pcap")
    assert report["packets"] == 5
    assert report["frames_with_changed_checksums"] == 5
    assert report["source_sha256"] != report["output_sha256"]
    out = (tmp_path / "fixed.pcap").read_bytes()
    raw = src.read_bytes()
    assert out[:24] == raw[:24]
    assert len(out) == len(raw)


def test_repair_pcap_refuses_to_overwrite(tmp_path):
    frames = [_ethernet_ipv4_tcp_frame()]
    src = _write_pcap(tmp_path / "raw.pcap", frames)
    dst = tmp_path / "fixed.pcap"
    dst.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        repair.repair_pcap(src, dst)
