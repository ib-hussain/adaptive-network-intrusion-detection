"""Regression tests for the strict staged sensor gate."""
from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from setup import staged_sensor_gate as gate


def _write_pcap(path: Path, packets: int = 3) -> Path:
    """Build a small classic pcap with structurally valid record framing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = b""
    for i in range(packets):
        body += struct.pack("<IIII", 1700000000 + i, 0, 4, 4) + b"\x45\x00\x00\x14"
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + body)
    return path


def _conn_rows_per_episode():
    """Four bidirectional TCP/8080 connections inside each fixture episode interval."""
    rows = []
    for i in range(4):
        for k in range(4):
            rows.append({
                "ts": 1700000000.0 + i * 100 + 10 + k * 10,
                "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2",
                "id.orig_p": 40000 + i * 10 + k, "id.resp_p": 8080,
                "proto": "tcp", "duration": 0.01,
                "orig_bytes": 100, "resp_bytes": 50,
            })
    return rows


def _manifest_rows():
    base = 1700000000.0
    rows = []
    for i in range(4):
        eid = f"e{i}"
        rows.append({
            "episode_id": eid,
            "condition": "incident" if i % 2 else "benign",
            "policy": "test" if i >= 2 else "fixed",
            "profile": "rapid_repeat",
            "start_ts": base + i * 100,
            "onset_ts": base + i * 100 + 20 if i % 2 else None,
            "escalation_ts": base + i * 100 + 40 if i % 2 else None,
            "milestone_ts": base + i * 100 + 60 if i % 2 else None,
            "end_ts": base + i * 100 + 90,
            "requests": 20,
        })
    return rows


def _write_run(root: Path, *, with_pcap=True, packets=3, complete=True):
    raw = root / "src" / "data" / "raw" / "runs" / "run_x"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / "episodes.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in _manifest_rows()), encoding="utf-8")
    (raw / "gateway_subset.jsonl").write_text(json.dumps({"sensor": "application_gateway"}) + "\n", encoding="utf-8")
    if complete:
        (raw / "complete.json").write_text(json.dumps({"schema": "staged_v2_1"}) + "\n", encoding="utf-8")
    if with_pcap:
        _write_pcap(raw / "traffic_0001.pcap", packets)
    return raw


def test_join_counts_ambiguous_and_outside(monkeypatch):
    manifest = {
        "a": {"episode_id": "a", "start_ts": 0.0, "end_ts": 10.0, "condition": "benign", "policy": "fixed"},
        "b": {"episode_id": "b", "start_ts": 20.0, "end_ts": 30.0, "condition": "incident", "policy": "fixed"},
    }
    rows = [
        {"ts": 5.0, "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "orig_bytes": 10, "resp_bytes": 20},
        {"ts": 25.0, "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "orig_bytes": 10, "resp_bytes": 20},
        {"ts": 99.0, "id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "orig_bytes": 10, "resp_bytes": 20},
    ]
    assigned, counts = gate.join_conn_to_episodes(rows, manifest)
    assert len(assigned) == 2
    assert counts["assigned_to_one_episode"] == 2
    assert counts["outside_any_episode"] == 1
    assert counts["ambiguous_timestamp_matches"] == 0


def test_missing_artefacts_is_invalid_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "INVALID_CAPTURE"
    assert report["checks"]["C1"]["passed"] is False
    assert out.is_file()
    with pytest.raises(FileExistsError):
        gate.evaluate("run_x", out)


def test_header_only_pcap_is_invalid_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    raw = _write_run(tmp_path)
    (raw / "traffic_0001.pcap").write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "INVALID_CAPTURE"
    assert report["checks"]["C2"]["passed"] is False


def test_missing_zeek_conn_is_invalid_capture(tmp_path, monkeypatch):
    """Structurally valid PCAP but Zeek yields no connections -> not network evidence."""
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    _write_run(tmp_path, packets=40)
    monkeypatch.setattr(gate, "find_zeek", lambda: "zeek")
    monkeypatch.setattr(gate, "_zeek_version", lambda _b: "zeek version test")
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "INVALID_CAPTURE"
    assert report["checks"]["C3"]["passed"] is False


def test_all_checks_pass_yields_sensor_validated(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    _write_run(tmp_path, packets=40)

    def fake_run_zeek(zeek_bin, pcap, workdir, ignore_checksums):
        workdir.mkdir(parents=True, exist_ok=True)
        rows = _conn_rows_per_episode()
        (workdir / "conn.log").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return {"pcap": pcap.name, "command": "zeek -r x", "ignore_checksums": ignore_checksums,
                "started_utc": "t", "finished_utc": "t", "returncode": 0, "stderr_tail": "",
                "conn_entries": len(rows), "weird_entries": 0, "checksum_weird_entries": 0,
                "checksum_weird_names": [], "_conn_rows": rows}

    monkeypatch.setattr(gate, "run_zeek", fake_run_zeek)
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "SENSOR_VALIDATED", report["failures"]
    assert report["checksum_validation_ignored"] is False
    assert report["checks"]["C5"]["bidirectional_fraction"] == 1.0
    assert report["checks"]["C7"]["test_episodes_with_windows"] == 2
    assert report["pcaps"][0]["sha256"]


def test_checksum_bypass_downgrades_to_conditional(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    _write_run(tmp_path, packets=40)

    def fake_run_zeek(zeek_bin, pcap, workdir, ignore_checksums):
        workdir.mkdir(parents=True, exist_ok=True)
        rows = _conn_rows_per_episode()
        (workdir / "conn.log").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return {"pcap": pcap.name, "command": "zeek -C -r x", "ignore_checksums": ignore_checksums,
                "started_utc": "t", "finished_utc": "t",
                "returncode": 0 if ignore_checksums else 1, "stderr_tail": "checksum error" if not ignore_checksums else "",
                "conn_entries": len(rows) if ignore_checksums else 0, "weird_entries": 0,
                "checksum_weird_entries": 3 if not ignore_checksums else 0,
                "checksum_weird_names": ["checksum_none"] if not ignore_checksums else [],
                "_conn_rows": rows if ignore_checksums else []}

    monkeypatch.setattr(gate, "run_zeek", fake_run_zeek)
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "ZEEK_CONDITIONAL"
    assert report["checksum_validation_ignored"] is True


def test_low_bidirectional_fraction_is_not_sensor_validated(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    _write_run(tmp_path, packets=40)

    def fake_run_zeek(zeek_bin, pcap, workdir, ignore_checksums):
        workdir.mkdir(parents=True, exist_ok=True)
        rows = _conn_rows_per_episode()
        for idx, row in enumerate(rows):
            if idx % 2:
                row["orig_bytes"] = 0
        (workdir / "conn.log").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return {"pcap": pcap.name, "command": "zeek -r x", "ignore_checksums": ignore_checksums,
                "started_utc": "t", "finished_utc": "t", "returncode": 0, "stderr_tail": "",
                "conn_entries": len(rows), "weird_entries": 0, "checksum_weird_entries": 0,
                "checksum_weird_names": [], "_conn_rows": rows}

    monkeypatch.setattr(gate, "run_zeek", fake_run_zeek)
    out = tmp_path / "audit" / "sensor_audit.json"
    report = gate.evaluate("run_x", out)
    assert report["evidence_tag"] == "PCAP_STRUCTURAL"
    assert report["checks"]["C5"]["passed"] is False
    assert report["checks"]["C5"]["bidirectional_fraction"] == 0.5
