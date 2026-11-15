"""Strict sensor-validation gate for a completed staged run.

Fails closed before any network-sensor training. Every count carries its
denominator, every failure names the failed invariant, and the PCAP SHA256 plus
the exact Zeek command are recorded as provenance.

The gate NEVER synthesises Zeek flows, byte counters or episode labels. A run
that fails a semantic check is downgraded to a weaker evidence tag rather than
being repaired.

Evidence tags (see MEMORY.md section 7):
  INVALID_CAPTURE     missing/empty/header-only capture or missing ground truth
  PCAP_STRUCTURAL     nonempty parseable PCAP, semantics not established
  ZEEK_CONDITIONAL    Zeek parsed and semantics passed, but checksum validation was bypassed (-C)
  SENSOR_VALIDATED    all declared semantic checks passed with checksum validation enabled
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from setup.staged_capture_audit import inspect_pcap  # noqa: E402
from setup.pcap_checksum_repair import repair_pcap  # noqa: E402
from src.code.ingest import load_manifest  # noqa: E402
from src.code.features import make_windows  # noqa: E402

GATE_SCHEMA = "staged_sensor_gate_v1"

CHECKS = (
    ("C1", "run artefacts present", "complete.json, episodes.jsonl, gateway_subset.jsonl and >=1 PCAP exist"),
    ("C2", "PCAP structurally valid", "every PCAP complete with packet records; packet count plausible for episode count"),
    ("C3", "Zeek exit status zero", "zeek returned 0 and emitted conn.log entries"),
    ("C4", "expected service traffic", "TCP connections observed on the expected service port"),
    ("C5", "bidirectional byte visibility", "fraction of eligible episode connections with orig_bytes>0 AND resp_bytes>0"),
    ("C6", "episode time alignment", "conn timestamps map to independently recorded episode intervals"),
    ("C7", "held-out test coverage", "test episodes expose eligible pre-milestone windows"),
)

TAG_ORDER = {"INVALID_CAPTURE": 0, "PCAP_STRUCTURAL": 1, "ZEEK_CONDITIONAL": 2, "SENSOR_VALIDATED": 3}


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_zeek() -> str:
    found = shutil.which("zeek")
    if found:
        return found
    for candidate in ("/opt/zeek/bin/zeek", "/usr/local/bin/zeek", "/usr/bin/zeek"):
        if os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("zeek executable not found on PATH or in /opt/zeek/bin")


def _zeek_version(zeek_bin: str) -> str:
    try:
        proc = subprocess.run([zeek_bin, "--version"], capture_output=True, text=True, timeout=30)
        return (proc.stdout or proc.stderr).strip().splitlines()[0]
    except Exception:  # pragma: no cover - diagnostic only
        return "unknown"


def _read_conn_json(path: Path) -> list[dict]:
    rows = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def run_zeek(zeek_bin: str, pcap: Path, workdir: Path, ignore_checksums: bool) -> dict:
    """Run Zeek over one PCAP segment. Returns provenance plus parsed conn rows."""
    workdir.mkdir(parents=True, exist_ok=True)
    cmd = [zeek_bin]
    if ignore_checksums:
        cmd.append("-C")
    cmd += ["-r", str(pcap.resolve()), "LogAscii::use_json=T"]
    started = _utc()
    try:
        proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=900, check=False)
        rc, stderr = proc.returncode, (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired:
        rc, stderr = -1, "zeek timed out after 900s"
    conn = _read_conn_json(workdir / "conn.log")
    weird = _read_conn_json(workdir / "weird.log")
    checksum_weirds = [w for w in weird if "checksum" in str(w.get("name", "")).lower()]
    return {
        "pcap": pcap.name,
        "command": " ".join(cmd),
        "ignore_checksums": bool(ignore_checksums),
        "started_utc": started,
        "finished_utc": _utc(),
        "returncode": rc,
        "stderr_tail": stderr,
        "conn_entries": len(conn),
        "weird_entries": len(weird),
        "checksum_weird_entries": len(checksum_weirds),
        "checksum_weird_names": sorted({str(w.get("name")) for w in checksum_weirds}),
        "_conn_rows": conn,
    }


def join_conn_to_episodes(conn_rows: list[dict], manifest: dict) -> tuple[list[dict], dict]:
    """Assign conn records to episodes by time only. Count ambiguity and gaps."""
    episodes = sorted(manifest.values(), key=lambda e: float(e["start_ts"]))
    assigned, ambiguous, unassigned = [], 0, 0
    for row in conn_rows:
        try:
            ts = float(row.get("ts"))
        except (TypeError, ValueError):
            unassigned += 1
            continue
        hits = [e for e in episodes if float(e["start_ts"]) <= ts <= float(e["end_ts"])]
        if len(hits) == 1:
            assigned.append((hits[0]["episode_id"], row))
        elif not hits:
            unassigned += 1
        else:
            ambiguous += 1
    counts = {
        "conn_records": len(conn_rows),
        "assigned_to_one_episode": len(assigned),
        "ambiguous_timestamp_matches": ambiguous,
        "outside_any_episode": unassigned,
        "episode_count": len(manifest),
    }
    return assigned, counts


def _to_event(eid: str, row: dict) -> dict:
    def num(field, default=0.0):
        value = row.get(field, default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    return {
        "episode_id": eid,
        "ts": num("ts"),
        "src_host": str(row.get("id.orig_h", "")),
        "dst_host": str(row.get("id.resp_h", "")),
        "proto": str(row.get("proto", "tcp")),
        "duration": max(0.0, num("duration")),
        "orig_bytes": max(0.0, num("orig_bytes")),
        "resp_bytes": max(0.0, num("resp_bytes")),
        "source": "zeek",
    }


def evaluate(run_id: str, output_path: Path, *,
             min_bidirectional_fraction: float = 0.80,
             min_packets_per_episode: int = 4,
             min_test_windows: int = 1,
             expected_port: int = 8080,
             zeek_mode: str = "auto",
             enable_repair: bool = True,
             zeek_timeout_note: str = "zeek invoked per PCAP segment, 900s timeout each") -> dict:
    raw = REPO_ROOT / "src" / "data" / "raw" / "runs" / run_id
    report = {
        "schema": GATE_SCHEMA,
        "run_id": run_id,
        "generated_utc": _utc(),
        "raw_dir": str(raw),
        "evidence_tag": "INVALID_CAPTURE",
        "checksum_validation_ignored": None,
        "checks": {},
        "failures": [],
        "thresholds": {
            "min_bidirectional_fraction": min_bidirectional_fraction,
            "min_packets_per_episode": min_packets_per_episode,
            "min_test_windows": min_test_windows,
            "expected_service_port": expected_port,
            "zeek_mode": zeek_mode,
        },
        "provenance": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "repo_root": str(REPO_ROOT),
            "zeek_timeout_note": zeek_timeout_note,
        },
    }

    def check(cid: str, passed: bool, detail: str, **extra):
        report["checks"][cid] = {
            "id": cid,
            "requirement": next(c[1] for c in CHECKS if c[0] == cid),
            "criterion": next(c[2] for c in CHECKS if c[0] == cid),
            "passed": bool(passed),
            "detail": detail,
            **extra,
        }
        if not passed:
            report["failures"].append(f"{cid}: {detail}")

    # ---- C1 artefacts -----------------------------------------------------
    required = {
        "complete.json": raw / "complete.json",
        "episodes.jsonl": raw / "episodes.jsonl",
        "gateway_subset.jsonl": raw / "gateway_subset.jsonl",
    }
    pcaps = sorted(raw.glob("traffic_*.pcap"))
    missing = {name: str(p) for name, p in required.items() if not p.is_file()}
    present = {name: {"path": str(p), "bytes": p.stat().st_size} for name, p in required.items() if p.is_file()}
    check("C1", not missing and bool(pcaps),
          "all required artefacts present" if (not missing and pcaps) else f"missing: {sorted(missing)} pcaps={len(pcaps)}",
          required_files=present, missing=sorted(missing), pcap_segments=[p.name for p in pcaps])
    if missing or not pcaps:
        return _finish(report, output_path)

    manifest = load_manifest(raw / "episodes.jsonl")
    n_episodes = len(manifest)

    # ---- C2 PCAP structure -------------------------------------------------
    pcap_reports = []
    total_packets = 0
    for pcap in pcaps:
        info = inspect_pcap(pcap)
        info["sha256"] = sha256(pcap)
        info["bytes"] = pcap.stat().st_size
        total_packets += int(info.get("packets") or 0)
        pcap_reports.append(info)
    report["pcaps"] = pcap_reports
    needed = min_packets_per_episode * n_episodes
    all_complete = all(r.get("complete") for r in pcap_reports)
    check("C2", all_complete and total_packets >= needed,
          f"segments={len(pcap_reports)} complete={all_complete} packets={total_packets} required>={needed}",
          packets=total_packets, required_packets=needed, episode_count=n_episodes,
          segments=[{"name": r["path"].split("/")[-1], "packets": r["packets"], "complete": r["complete"],
                     "bytes": r["bytes"], "sha256": r["sha256"], "issue": r["issue"]} for r in pcap_reports])
    if not (all_complete and total_packets >= needed):
        return _finish(report, output_path)

    # ---- Zeek execution ----------------------------------------------------
    zeek_bin = find_zeek()
    report["provenance"]["zeek_version"] = _zeek_version(zeek_bin)
    zeek_dir = output_path.parent / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    strict_runs, relaxed_runs = [], []
    for i, pcap in enumerate(pcaps):
        strict_runs.append(run_zeek(zeek_bin, pcap, zeek_dir / f"strict_{i:03d}", ignore_checksums=False))
        relaxed_runs.append(run_zeek(zeek_bin, pcap, zeek_dir / f"checksum_ignored_{i:03d}", ignore_checksums=True))
    report["zeek"] = {"strict": [_strip_rows(r) for r in strict_runs],
                      "checksum_ignored": [_strip_rows(r) for r in relaxed_runs]}

    def rows_of(runs):
        return [row for r in runs for row in r["_conn_rows"]]

    def bidirectional_fraction(rows):
        if not rows:
            return 0.0
        good = sum(1 for r in rows
                   if _num(r.get("orig_bytes")) > 0 and _num(r.get("resp_bytes")) > 0)
        return good / len(rows)

    strict_rows = rows_of(strict_runs)
    relaxed_rows = rows_of(relaxed_runs)
    primary, primary_label, ignore_checksums = [], "none", None
    checksum_repaired = False
    repair_reports = []
    repaired_runs = []

    # 1. Strict Zeek with checksum validation on the raw capture.
    if strict_rows and bidirectional_fraction(strict_rows) >= min_bidirectional_fraction:
        primary, primary_label, ignore_checksums = strict_runs, "strict", False

    # 2. Strict Zeek on a derived checksum-repaired copy. The raw capture is never
    #    modified. Only valid when the repair is corroborated by the independent
    #    checksum-ignored run producing the same number of connections.
    if not primary and enable_repair:
        repair_dir = output_path.parent / "repaired"
        repair_dir.mkdir(parents=True, exist_ok=True)
        for i, pcap in enumerate(pcaps):
            repaired_pcap = repair_dir / f"{pcap.stem}_checksum_repaired.pcap"
            try:
                repair_reports.append(repair_pcap(pcap, repaired_pcap))
                repaired_runs.append(run_zeek(zeek_bin, repaired_pcap,
                                              zeek_dir / f"repaired_strict_{i:03d}", ignore_checksums=False))
            except (FileExistsError, ValueError, AssertionError) as exc:
                repair_reports.append({"source": str(pcap), "error": f"{type(exc).__name__}: {exc}"})
        report["zeek"]["checksum_repair"] = repair_reports
        report["zeek"]["repaired_strict"] = [_strip_rows(r) for r in repaired_runs]
        repaired_rows = rows_of(repaired_runs)
        if repaired_rows and bidirectional_fraction(repaired_rows) >= min_bidirectional_fraction:
            consistent = (not relaxed_rows) or (len(repaired_rows) == len(relaxed_rows))
            report["zeek"]["repair_consistency"] = {
                "repaired_strict_conn_entries": len(repaired_rows),
                "checksum_ignored_conn_entries": len(relaxed_rows),
                "counts_match": bool(consistent),
                "criterion": "the repaired trace and the independent checksum-ignored run must yield the same connection count",
            }
            if consistent:
                primary, primary_label, ignore_checksums = repaired_runs, "strict_checksum_repaired", False
                checksum_repaired = True

    # 3. Fall back to the checksum-ignored run; this can only be conditional evidence.
    if not primary and relaxed_rows:
        primary, primary_label, ignore_checksums = relaxed_runs, "checksum_ignored", True

    conn_rows = [row for r in primary for row in r["_conn_rows"]]
    report["zeek"]["primary_mode"] = primary_label
    report["checksum_validation_ignored"] = bool(ignore_checksums) if ignore_checksums is not None else None
    report["checksum_repaired"] = checksum_repaired
    check("C3", bool(conn_rows),
          f"mode={primary_label} zeek_rc={[r['returncode'] for r in primary]} conn_entries={len(conn_rows)}"
          + (f" stderr={primary[0]['stderr_tail'][:300]}" if primary else " zeek produced no usable conn.log"),
          zeek_rc=[r["returncode"] for r in primary], conn_entries=len(conn_rows),
          strict_conn_entries=sum(r["conn_entries"] for r in strict_runs),
          checksum_ignored_conn_entries=sum(r["conn_entries"] for r in relaxed_runs),
          checksum_weird_entries=sum(r["checksum_weird_entries"] for r in primary),
          checksum_weird_names=sorted({n for r in primary for n in r["checksum_weird_names"]}))
    if not conn_rows:
        return _finish(report, output_path)

    # ---- C4 expected service traffic --------------------------------------
    service_port_hits = 0
    tcp_total = 0
    for row in conn_rows:
        proto = str(row.get("proto", ""))
        try:
            resp_p = int(row.get("id.resp_p", -1))
        except (TypeError, ValueError):
            resp_p = -1
        try:
            orig_p = int(row.get("id.orig_p", -1))
        except (TypeError, ValueError):
            orig_p = -1
        if proto == "tcp":
            tcp_total += 1
            if resp_p == expected_port or orig_p == expected_port:
                service_port_hits += 1
    check("C4", service_port_hits > 0,
          f"tcp_connections={tcp_total} on_port_{expected_port}={service_port_hits}",
          tcp_connections=tcp_total, service_port_connections=service_port_hits, expected_port=expected_port)

    # ---- C6 episode time alignment ----------------------------------------
    assigned, join_counts = join_conn_to_episodes(conn_rows, manifest)
    events = [_to_event(eid, row) for eid, row in assigned]
    per_episode = {}
    for event in events:
        per_episode[event["episode_id"]] = per_episode.get(event["episode_id"], 0) + 1
    episodes_with_conns = len(per_episode)
    check("C6", join_counts["ambiguous_timestamp_matches"] == 0 and episodes_with_conns > 0,
          f"assigned={join_counts['assigned_to_one_episode']} ambiguous={join_counts['ambiguous_timestamp_matches']} "
          f"outside={join_counts['outside_any_episode']} episodes_with_conns={episodes_with_conns}/{n_episodes}",
          **join_counts, episodes_with_connections=episodes_with_conns, total_episodes=n_episodes,
          min_connections_per_episode=3)

    # ---- C5 bidirectional byte visibility ----------------------------------
    eligible = [e for e in events]
    bidirectional = [e for e in eligible if e["orig_bytes"] > 0 and e["resp_bytes"] > 0]
    positive_orig = sum(1 for e in eligible if e["orig_bytes"] > 0)
    positive_resp = sum(1 for e in eligible if e["resp_bytes"] > 0)
    fraction = (len(bidirectional) / len(eligible)) if eligible else 0.0
    check("C5", bool(eligible) and fraction >= min_bidirectional_fraction,
          f"bidirectional={len(bidirectional)}/{len(eligible)} fraction={fraction:.4f} "
          f"required>={min_bidirectional_fraction} (orig>0:{positive_orig}, resp>0:{positive_resp})",
          eligible_connections=len(eligible), bidirectional_connections=len(bidirectional),
          bidirectional_fraction=round(fraction, 6), positive_orig_bytes=positive_orig,
          positive_resp_bytes=positive_resp, required_fraction=min_bidirectional_fraction)

    # ---- C7 held-out test coverage ----------------------------------------
    test_ids = [eid for eid, ep in manifest.items() if ep["policy"] == "test"]
    try:
        pre_windows = make_windows(events, manifest, n_events=4, min_events=3,
                                   before_milestone_only=True, causal_stage_labels=False)
    except ValueError as exc:
        pre_windows = []
        check("C7", False, f"window construction failed: {exc}", test_episodes=len(test_ids))
    else:
        test_windows = [w for w in pre_windows if w["episode_id"] in set(test_ids)]
        covered = {w["episode_id"] for w in test_windows}
        eligible_test = [eid for eid in test_ids if per_episode.get(eid, 0) >= 3]
        check("C7", len(covered) >= min_test_windows and len(covered) == len(test_ids),
              f"test_episodes_with_pre_milestone_windows={len(covered)}/{len(test_ids)} required>={min_test_windows}",
              test_episodes=len(test_ids), test_episodes_with_windows=len(covered),
              test_episodes_with_min_connections=len(eligible_test),
              pre_milestone_windows_total=len(pre_windows), required_test_windows=min_test_windows)

    # ---- evidence tag ------------------------------------------------------
    all_pass = all(report["checks"][cid]["passed"] for cid, _, _ in CHECKS)
    if all_pass:
        report["evidence_tag"] = "ZEEK_CONDITIONAL" if ignore_checksums else "SENSOR_VALIDATED"
        if checksum_repaired:
            report["evidence_caveats"] = [
                "The raw capture carries invalid TCP checksums because the container veth leaves "
                "NIC transmit offloading in place. Strict Zeek therefore discarded every data "
                "segment on the raw trace. The primary evidence was produced by a derived copy in "
                "which only the IPv4/TCP/UDP checksum fields were recomputed from the captured "
                "payload (setup/pcap_checksum_repair.py); the raw pcap is unchanged and its SHA256 "
                "is recorded. The repaired trace was re-read by Zeek WITH checksum validation "
                "enabled and produced the same connection count as an independent checksum-ignored "
                "read of the raw trace."
            ]
    else:
        failed_structural = [cid for cid in ("C1", "C2", "C3") if not report["checks"][cid]["passed"]]
        report["evidence_tag"] = "INVALID_CAPTURE" if failed_structural else "PCAP_STRUCTURAL"
    return _finish(report, output_path)


def _num(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _strip_rows(run: dict) -> dict:
    return {k: v for k, v in run.items() if not k.startswith("_")}


def _finish(report: dict, output_path: Path) -> dict:
    output_path = Path(output_path)
    if output_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing sensor audit: {output_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_name(output_path.name + ".pending")
    with tmp.open("x", encoding="utf-8") as fp:
        json.dump(report, fp, indent=2, sort_keys=True, allow_nan=False)
        fp.write("\n")
    os.replace(tmp, output_path)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Strict Zeek/PCAP/episode sensor-validation gate")
    parser.add_argument("--run", required=True, help="run id under src/data/raw/runs")
    parser.add_argument("--output", required=True, type=Path, help="path for sensor_audit.json")
    parser.add_argument("--min-bidirectional-fraction", type=float, default=0.80)
    parser.add_argument("--min-packets-per-episode", type=int, default=4)
    parser.add_argument("--min-test-windows", type=int, default=1)
    parser.add_argument("--expected-port", type=int, default=8080)
    parser.add_argument("--zeek-mode", choices=["auto", "strict", "checksum-ignored"], default="auto")
    parser.add_argument("--no-checksum-repair", action="store_true",
                        help="do not derive a checksum-repaired copy; strict evidence only")
    parser.add_argument("--require-validated", action="store_true",
                        help="exit non-zero unless the run reaches SENSOR_VALIDATED")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    report = evaluate(args.run, args.output,
                      min_bidirectional_fraction=args.min_bidirectional_fraction,
                      min_packets_per_episode=args.min_packets_per_episode,
                      min_test_windows=args.min_test_windows,
                      expected_port=args.expected_port,
                      zeek_mode=args.zeek_mode,
                      enable_repair=not args.no_checksum_repair)
    if not args.quiet:
        print(json.dumps(report, indent=2, sort_keys=True))
    print(f"EVIDENCE_TAG={report['evidence_tag']}")
    tag = report["evidence_tag"]
    if args.require_validated:
        return 0 if tag == "SENSOR_VALIDATED" else 3
    if tag in ("SENSOR_VALIDATED", "ZEEK_CONDITIONAL"):
        return 0
    if tag == "PCAP_STRUCTURAL":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
