"""Record the exact execution environment for the reproducibility bundle."""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

TRACKED_ENV_VARS = (
    "PYTHONUNBUFFERED", "PYTHONHASHSEED", "TOKENIZERS_PARALLELISM", "CUDA_VISIBLE_DEVICES",
    "OMP_NUM_THREADS", "MKL_NUM_THREADS", "OPENBLAS_NUM_THREADS", "NUMEXPR_NUM_THREADS",
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
)

CORE_SCRIPTS = (
    "setup/staged_collect_v3.sh", "setup/staged_zeek.py", "setup/staged_sensor_gate.py",
    "setup/staged_capture_audit.py", "setup/staged_train_guard_v3.sh", "setup/staged_train_start.sh",
    "lab/staged_generate.py", "lab/http_service.py", "src/code/ingest.py", "src/code/features.py",
    "src/code/models.py", "src/code/pipeline.py", "src/code/early_warning.py", "src/code/game.py",
    "src/code/figures.py", "src/code/temporal_gru_sprint.py", "compose.yaml", "requirements.txt",
)


def _run(cmd):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return (proc.stdout or proc.stderr).strip()
    except Exception as exc:  # pragma: no cover - diagnostic only
        return f"UNAVAILABLE ({type(exc).__name__}: {exc})"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect() -> str:
    lines = []
    add = lines.append
    add("=== Phase 3 execution environment ===")
    add(f"generated_utc={datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    add(f"repo_root={REPO_ROOT}")
    add(f"python_executable={sys.executable}")
    add(f"python_version={sys.version.replace(chr(10), ' ')}")
    add(f"platform={platform.platform()}")
    add(f"machine={platform.machine()}")
    add(f"processor={platform.processor()}")
    add("")
    add("--- operating system ---")
    add(_run(["uname", "-a"]))
    add("")
    add("--- cpu / memory ---")
    add(_run(["lscpu"]))
    add(_run(["free", "-h"]))
    add("")
    add("--- storage ---")
    add(_run(["df", "-h"]))
    add("")
    add("--- python packages (pip freeze) ---")
    add(_run([sys.executable, "-m", "pip", "freeze"]))
    add("")
    add("--- key runtime libraries ---")
    add(_run([sys.executable, "-c",
              "import torch,numpy,pandas,sklearn,optuna,matplotlib;"
              "print('torch',torch.__version__,'cuda_available',torch.cuda.is_available());"
              "print('numpy',numpy.__version__);print('pandas',pandas.__version__);"
              "print('sklearn',sklearn.__version__);print('optuna',optuna.__version__);"
              "print('matplotlib',matplotlib.__version__)"]))
    add("")
    add("--- docker ---")
    add(_run(["docker", "--version"]))
    add(_run(["docker", "compose", "version"]))
    add(f"docker_root_dir={_run(['docker', 'info', '--format', '{{.DockerRootDir}}'])}")
    add("")
    add("--- zeek / tcpdump ---")
    add(_run(["zeek", "--version"]))
    add(_run(["tcpdump", "--version"]))
    add("")
    add("--- relevant environment variables ---")
    for name in TRACKED_ENV_VARS:
        add(f"{name}={os.environ.get(name, '<unset>')}")
    add("")
    add("--- sha256 of core scripts ---")
    for rel in CORE_SCRIPTS:
        path = REPO_ROOT / rel
        if path.is_file():
            add(f"{_sha256(path)}  {rel}")
        else:
            add(f"<missing>  {rel}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write the environment record to this path")
    args = parser.parse_args()
    text = collect()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            raise FileExistsError(f"Refusing to overwrite: {args.output}")
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()
