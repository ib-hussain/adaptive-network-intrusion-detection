"""Build the Phase 3 submission evidence bundle (fail-closed).

The repository tracks source, documentation and *derived* study tables but
deliberately excludes raw evidence: PCAPs, ``src/data/raw/*``, GRU checkpoints
and SQLite files are Git-ignored. This tool gathers the report-referenced
artefacts plus the raw run directories into one directory, writes a manifest,
a checksum list and a reproduction guide, and then produces a single ZIP.

It never generates, infers or repairs data. If any required raw artefact is
missing it stops with exit code 2 and prints the exact missing paths.

Usage::

    python -m setup.package_phase3_submission --help
    python -m setup.package_phase3_submission            # defaults to the final runs

The ZIP is written **outside** the repository by default so that large packet
records can never be committed by accident.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

PRIMARY_RUN = "cpu_v3_main_v2_20261115T164430Z"
SEED2_RUN = "cpu_v3_main_v2_seed2_20261115T165949Z"
PRIMARY_ZEEK_STUDY = f"outputs/studies/{PRIMARY_RUN}_zeek_20261115T165446Z"
PRIMARY_GATEWAY_STUDY = f"outputs/studies/{PRIMARY_RUN}_gateway_20261115T165446Z"
PRIMARY_GRU_STUDY = f"outputs/studies/{PRIMARY_RUN}_gru_zeek"
SEED2_ZEEK_STUDY = f"outputs/studies/{SEED2_RUN}_zeek_20261115T170436Z"
SEED2_GRU_STUDY = f"outputs/studies/{SEED2_RUN}_gru_zeek"

REQUIRED_RUN_FILES = (
    "complete.json",
    "episodes.jsonl",
    "game_rounds.jsonl",
    "gateway_subset.jsonl",
    "scenario_config.json",
)

STUDY_FILES = (
    "metrics.csv",
    "ablations.csv",
    "results.json",
    "test_predictions.jsonl",
)
STUDY_DATASET_FILES = (
    "dataset/dataset_manifest.json",
    "dataset/feature_schema.json",
    "dataset/leakage_audit.json",
    "dataset/preprocessing_report.json",
    "dataset/split_manifest.jsonl",
    "dataset/windows.csv",
)


class PackagingError(RuntimeError):
    """Raised when required evidence is missing or the target is unsafe."""


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _require(paths: Iterable[Path]) -> None:
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        raise PackagingError("missing required evidence:\n  " + "\n  ".join(missing))


def _run_files(repo: Path, run_id: str) -> list[Path]:
    raw = repo / "src" / "data" / "raw" / "runs" / run_id
    files = [raw / name for name in REQUIRED_RUN_FILES]
    files.extend(sorted(raw.glob("traffic_*.pcap")))
    return files


def collect_required(repo: Path, run_id: str) -> dict[str, list[Path]]:
    """Return the required raw artefacts for one run, validated to exist.

    Split out from :func:`main` so the failure mode can be unit-tested without
    building a ZIP.
    """

    raw = repo / "src" / "data" / "raw" / "runs" / run_id
    missing: list[str] = []
    for name in REQUIRED_RUN_FILES:
        if not (raw / name).is_file():
            missing.append(str(raw / name))
    pcaps = sorted(raw.glob("traffic_*.pcap"))
    if not pcaps:
        missing.append(str(raw / "traffic_*.pcap"))
    if missing:
        raise PackagingError(
            f"run {run_id} is missing required raw evidence:\n  " + "\n  ".join(missing)
        )
    optional_logs = sorted(raw.glob("*collector*.log")) + sorted(
        raw.glob("*generator*.log")
    ) + sorted(raw.glob("*capture_container*.log"))
    rounds = raw / "rounds"
    return {
        "raw_required": [raw / name for name in REQUIRED_RUN_FILES],
        "raw_pcap": pcaps,
        "raw_logs": optional_logs,
        "raw_rounds": sorted(rounds.glob("*.json")) if rounds.is_dir() else [],
    }


def _study_files(repo: Path, rel: str) -> list[Path]:
    study = repo / rel
    files = [study / name for name in STUDY_FILES]
    files.extend(study / name for name in STUDY_DATASET_FILES)
    return files


def _gru_files(repo: Path, rel: str) -> list[Path]:
    gru = repo / rel
    files: list[Path] = []
    for policy in ("fixed", "random", "strategic"):
        files.extend(
            gru / policy / name for name in ("complete.json", "epochs.jsonl", "latest.pt")
        )
    return files


def _figure_files(repo: Path, report_rel: str) -> list[Path]:
    figures = repo / report_rel / "figures"
    return sorted(p for p in figures.rglob("*") if p.is_file())


def _latest_dir(repo: Path, rel: str) -> Path | None:
    base = repo / rel
    if not base.is_dir():
        return None
    candidates = sorted(p for p in base.iterdir() if p.is_dir())
    return candidates[-1] if candidates else None


def _source_hashes(repo: Path) -> dict[str, str]:
    """SHA256 of tracked source/documentation files (never raw data)."""

    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "ls-files"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        raise PackagingError(f"cannot list tracked files: {exc}") from exc
    prefixes = ("lab/", "src/code/", "setup/", "tools/", "tests/", "configs/", "docs/")
    hashes: dict[str, str] = {}
    for rel in out.splitlines():
        if not rel.startswith(prefixes):
            continue
        path = repo / rel
        if path.is_file() and path.suffix in {".py", ".sh", ".json", ".yaml", ".yml", ".md"}:
            hashes[rel] = sha256_file(path)
    return hashes


def _git_state(repo: Path) -> dict[str, object]:
    def run(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    porcelain = run("status", "--porcelain")
    dirty_paths = [line[3:] for line in porcelain.splitlines() if line.strip()]
    return {
        "commit": run("rev-parse", "HEAD"),
        "branch": run("rev-parse", "--abbrev-ref", "HEAD"),
        "describe": run("describe", "--always", "--dirty"),
        "dirty": bool(dirty_paths),
        "dirty_paths": dirty_paths,
    }


def _test_summary(verification_dir: Path) -> dict:
    """Read the real pytest result from the verification log.

    The manifest must never carry a hard-coded test count; if the log has no
    recognisable result the packager fails rather than quoting an old number.
    """

    log = verification_dir / "verification.log"
    if not log.is_file():
        raise PackagingError(f"verification log missing: {log}")
    text = log.read_text(encoding="utf-8", errors="replace")
    passed = re.findall(r"(\d+) passed", text)
    rc = re.findall(r"pytest_rc=(\d+)", text)
    if not passed or not rc:
        raise PackagingError(f"cannot read a pytest result from {log}")
    return {"passed": int(passed[-1]), "pytest_rc": int(rc[-1]), "log": str(log)}


def _copy_tree(files: Iterable[Path], repo: Path, staging: Path) -> list[str]:
    copied: list[str] = []
    for src in files:
        rel = src.resolve().relative_to(repo.resolve())
        dst = staging / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(str(rel))
    return copied


def _write_reproduce_guide(staging: Path, manifest: dict) -> None:
    text = f"""# Phase 3 submission evidence bundle

Run IDs: `{manifest['runs']['primary']['run_id']}` (seed {manifest['runs']['primary']['seed']})
and `{manifest['runs']['seed2']['run_id']}` (seed {manifest['runs']['seed2']['seed']}).

Repository commit: `{manifest['repository']['commit']}` (branch
`{manifest['repository']['branch']}`, describe `{manifest['repository']['describe']}`).

## What is here

* `outputs/reports/<run>/` — the canonical report, claim-to-artifact table,
  seed comparison, run inventories, GRU metrics, figures and their source data.
* `outputs/audits/<run>/` — the strict sensor gate output and the strict /
  checksum-repaired Zeek connection logs.
* `outputs/studies/<run>_*/` — the derived dataset, metrics, ablations and
  results used by the report.
* `src/data/raw/runs/<run>/` — the raw evidence: controller journal, gateway
  log, game rounds, scenario configuration, PCAP(s) and collector logs.
* `outputs/environment/` and `outputs/logs/final_verification/` — the recorded
  environment and the verification run.
* `deliverables/phase3_submission/` — submission-ready Markdown report, figures
  and claim table.
* `submission_manifest.json`, `SHA256SUMS.txt` — this bundle's manifest and
  per-file hashes.

## Verify

```bash
sha256sum -c SHA256SUMS.txt
```

## Reproduce the analysis without re-capturing

```bash
python -m setup.verify_report_numbers \\
  --zeek-study {manifest['studies']['primary_zeek']} \\
  --gateway-study {manifest['studies']['primary_gateway']} \\
  --gru-csv outputs/reports/{manifest['runs']['primary']['run_id']}/gru_metrics.csv \\
  --audit outputs/audits/{manifest['runs']['primary']['run_id']}/sensor_audit.json \\
  --inventory outputs/reports/{manifest['runs']['primary']['run_id']}/run_inventory.json \\
  --seed2-study {manifest['studies']['seed2_zeek']} \\
  --seed2-gru-csv outputs/reports/{manifest['runs']['seed2']['run_id']}/gru_metrics.csv
```

Expected: `{{"checks_performed": 102, "mismatches": [], "status": "PASS"}}`.

## Reproduce the capture

`README.md` §B and report §10.2 give the exact collection command. A new
capture needs Docker Compose and Zeek; it creates a new run ID and never
overwrites these runs.

## Archive hash

The ZIP cannot contain its own hash; it is recorded in `ARCHIVE.sha256` next
to the archive, together with `ARCHIVE_INFO.json`.
"""
    (staging / "README_REPRODUCE.md").write_text(text, encoding="utf-8")


def _zip_dir(source: Path, archive: Path) -> None:
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(source).as_posix())


def _unzip_test(archive: Path) -> str:
    try:
        out = subprocess.run(
            ["unzip", "-t", str(archive)], check=True, capture_output=True, text=True
        )
        return (out.stdout or "").strip().splitlines()[-1]
    except FileNotFoundError:  # pragma: no cover
        raise PackagingError("`unzip` is required to verify the archive but is not installed")
    except subprocess.CalledProcessError as exc:  # pragma: no cover
        raise PackagingError(f"archive failed `unzip -t`: {exc.stderr}") from exc


def build(
    repo: Path,
    *,
    primary: str,
    seed2: str,
    primary_zeek: str,
    primary_gateway: str,
    seed2_zeek: str,
    output_dir: Path,
    log=lambda msg: print(msg, flush=True),
) -> dict:
    if _is_within(output_dir, repo):
        raise PackagingError(
            f"refusing to write the archive inside the repository: {output_dir}\n"
            "Choose a directory outside the Git working tree."
        )

    stamp = _utc_stamp()
    primary_report = f"outputs/reports/{primary}"
    seed2_report = f"outputs/reports/{seed2}"

    required: list[Path] = []
    for run_id in (primary, seed2):
        raw = collect_required(repo, run_id)
        for group in raw.values():
            required.extend(group)
        required.append(repo / "outputs" / "audits" / run_id / "sensor_audit.json")

    for rel in (primary_zeek, primary_gateway, seed2_zeek):
        required.extend(_study_files(repo, rel))

    required.extend(
        [
            repo / primary_report / "PHASE3_REPORT.md",
            repo / primary_report / "claim_artifact_table.csv",
            repo / primary_report / "seed_comparison.csv",
            repo / primary_report / "run_inventory.json",
            repo / primary_report / "gru_metrics.csv",
            repo / primary_report / "report_number_verification.json",
            repo / primary_report / "literature_comparison.csv",
            repo / primary_report / "runtime_resources.csv",
            repo / seed2_report / "run_inventory.json",
            repo / seed2_report / "gru_metrics.csv",
        ]
    )
    required.extend(_gru_files(repo, PRIMARY_GRU_STUDY))
    required.extend(_gru_files(repo, SEED2_GRU_STUDY))
    required.extend(_figure_files(repo, primary_report))

    environment_dir = repo / "outputs" / "environment"
    environment_files = (
        sorted(p for p in environment_dir.iterdir() if p.is_file())
        if environment_dir.is_dir()
        else []
    )
    if not environment_files:
        raise PackagingError(
            "no environment record found under outputs/environment/ "
            "(run `python -m setup.record_environment` first)"
        )
    required.extend(environment_files)
    verification = _latest_dir(repo, "outputs/logs/final_verification")
    if verification is None:
        raise PackagingError(
            "no final verification log found under outputs/logs/final_verification/"
        )
    required.extend(sorted(p for p in verification.iterdir() if p.is_file()))

    deliverables = repo / "deliverables" / "phase3_submission"
    if deliverables.is_dir():
        required.extend(sorted(p for p in deliverables.rglob("*") if p.is_file()))

    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise PackagingError("missing required evidence:\n  " + "\n  ".join(sorted(missing)))

    staging = output_dir / f"phase3_submission_{stamp}"
    if staging.exists():
        raise PackagingError(f"staging directory already exists: {staging}")
    staging.mkdir(parents=True)
    log(f"[package] staging {staging}")

    copied = _copy_tree(required, repo, staging)

    def load_seed(run_id: str) -> int:
        cfg = json.loads((repo / "src" / "data" / "raw" / "runs" / run_id / "scenario_config.json").read_text())
        return int(cfg["seed"])

    pcap_hashes = {}
    for run_id in (primary, seed2):
        for pcap in sorted((repo / "src/data/raw/runs" / run_id).glob("traffic_*.pcap")):
            pcap_hashes[str(pcap.relative_to(repo))] = {
                "sha256": sha256_file(pcap),
                "bytes": pcap.stat().st_size,
            }

    manifest = {
        "schema": "phase3_submission_manifest_v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "repository": _git_state(repo),
        "runs": {
            "primary": {"run_id": primary, "seed": load_seed(primary)},
            "seed2": {"run_id": seed2, "seed": load_seed(seed2)},
        },
        "studies": {
            "primary_zeek": primary_zeek,
            "primary_gateway": primary_gateway,
            "seed2_zeek": seed2_zeek,
            "primary_gru": PRIMARY_GRU_STUDY,
            "seed2_gru": SEED2_GRU_STUDY,
        },
        "pcaps": pcap_hashes,
        "source_hashes": _source_hashes(repo),
        "file_count": len(copied),
        "verification": {
            "tests": _test_summary(verification),
            "report_numbers": json.loads(
                (repo / primary_report / "report_number_verification.json").read_text()
            ),
        },
    }
    (staging / "submission_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _write_reproduce_guide(staging, manifest)

    sums = []
    for path in sorted(p for p in staging.rglob("*") if p.is_file()):
        sums.append(f"{sha256_file(path)}  {path.relative_to(staging).as_posix()}")
    (staging / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

    archive = output_dir / f"phase3_submission_{stamp}.zip"
    log(f"[package] writing archive {archive}")
    _zip_dir(staging, archive)
    archive_sha = sha256_file(archive)
    archive_size = archive.stat().st_size
    (output_dir / "ARCHIVE.sha256").write_text(f"{archive_sha}  {archive.name}\n")
    (output_dir / "ARCHIVE_INFO.json").write_text(
        json.dumps(
            {
                "archive": str(archive),
                "bytes": archive_size,
                "sha256": archive_sha,
                "file_count": len(copied),
                "unzip_test": _unzip_test(archive),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    log(f"[package] archive {archive_size} bytes sha256={archive_sha}")
    log(f"[package] unzip -t: {_unzip_test(archive)}")
    return {
        "staging": str(staging),
        "archive": str(archive),
        "bytes": archive_size,
        "sha256": archive_sha,
        "manifest": str(staging / "submission_manifest.json"),
    }


def main(argv: list[str] | None = None) -> int:
    repo = _repo_root()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", default=PRIMARY_RUN, help="primary raw run id")
    parser.add_argument("--seed2-run", default=SEED2_RUN, help="replication raw run id")
    parser.add_argument("--zeek-study", default=PRIMARY_ZEEK_STUDY)
    parser.add_argument("--gateway-study", default=PRIMARY_GATEWAY_STUDY)
    parser.add_argument("--seed2-zeek-study", default=SEED2_ZEEK_STUDY)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=repo.parent / f"{repo.name}-submission",
        help="directory for the staging tree and ZIP; must be outside the repository",
    )
    args = parser.parse_args(argv)

    try:
        result = build(
            repo,
            primary=args.run,
            seed2=args.seed2_run,
            primary_zeek=args.zeek_study,
            primary_gateway=args.gateway_study,
            seed2_zeek=args.seed2_zeek_study,
            output_dir=args.output_dir,
        )
    except PackagingError as exc:
        print(f"[package] FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
