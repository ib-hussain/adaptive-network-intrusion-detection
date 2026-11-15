"""Regression tests for the fail-closed submission packager.

These tests never build a multi-megabyte archive; they exercise the guards that
must stop packaging before any ZIP is produced.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from setup import package_phase3_submission as pkg


def _make_run(root: Path, run_id: str, *, pcap: bool = True) -> Path:
    raw = root / "src" / "data" / "raw" / "runs" / run_id
    raw.mkdir(parents=True)
    for name in pkg.REQUIRED_RUN_FILES:
        (raw / name).write_text("{}", encoding="utf-8")
    if pcap:
        (raw / "traffic_20261115T000000Z_1.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
    return raw


def test_collect_required_accepts_a_complete_run(tmp_path: Path) -> None:
    run_id = "cpu_test_run"
    _make_run(tmp_path, run_id)
    files = pkg.collect_required(tmp_path, run_id)
    assert files["raw_required"]
    assert len(files["raw_pcap"]) == 1
    assert files["raw_pcap"][0].name.startswith("traffic_")


def test_collect_required_rejects_missing_pcap(tmp_path: Path) -> None:
    run_id = "cpu_test_run"
    _make_run(tmp_path, run_id, pcap=False)
    with pytest.raises(pkg.PackagingError) as excinfo:
        pkg.collect_required(tmp_path, run_id)
    assert "traffic_*.pcap" in str(excinfo.value)


def test_collect_required_names_every_missing_file(tmp_path: Path) -> None:
    run_id = "cpu_test_run"
    raw = _make_run(tmp_path, run_id)
    (raw / "gateway_subset.jsonl").unlink()
    (raw / "complete.json").unlink()
    with pytest.raises(pkg.PackagingError) as excinfo:
        pkg.collect_required(tmp_path, run_id)
    message = str(excinfo.value)
    assert "gateway_subset.jsonl" in message
    assert "complete.json" in message


def test_build_refuses_to_write_inside_the_repository(tmp_path: Path) -> None:
    repo = pkg._repo_root()
    with pytest.raises(pkg.PackagingError) as excinfo:
        pkg.build(
            repo,
            primary="missing",
            seed2="missing",
            primary_zeek="whatever",
            primary_gateway="whatever",
            seed2_zeek="whatever",
            output_dir=repo / "outputs" / "should-not-exist",
            log=lambda _msg: None,
        )
    assert "inside the repository" in str(excinfo.value)


def test_is_within_matches_only_real_descendants(tmp_path: Path) -> None:
    parent = tmp_path / "project"
    parent.mkdir()
    assert pkg._is_within(parent / "sub", parent)
    assert not pkg._is_within(tmp_path / "project-copy", parent)
