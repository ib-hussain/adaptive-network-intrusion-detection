"""Non-isolated loopback-only integration smoke. Never cite these results as research evidence."""
import argparse
import json
import sys
import tempfile
import threading
import time
from pathlib import Path

from lab.http_service import serve
from lab.generate import run
from src.code.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", help="Output directory (must not already contain files)")
    parser.add_argument("--episodes", type=int, default=4)
    args = parser.parse_args()
    output = Path(args.output) if args.output else Path(tempfile.mkdtemp(prefix="phase3_loopback_smoke_"))
    raw = output / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    threads = [
        threading.Thread(target=serve, args=("service", 18081), kwargs={"bind": "127.0.0.1"}, daemon=True),
        threading.Thread(target=serve, args=("service", 18082), kwargs={"bind": "127.0.0.1"}, daemon=True),
        threading.Thread(target=serve, args=("gateway", 18080, str(raw / "gateway_requests.jsonl")),
                         kwargs={"destinations": {"a": "http://127.0.0.1:18081/ping", "b": "http://127.0.0.1:18082/ping"},
                                 "bind": "127.0.0.1"}, daemon=True),
    ]
    for thread in threads:
        thread.start()
    time.sleep(.2)
    manifest = run(raw, "http://127.0.0.1:18080", episodes=args.episodes, test_episodes=args.episodes, delay_scale=.25)
    expected = 4 * 2 * args.episodes * 12
    event_path = raw / "gateway_requests.jsonl"
    for _ in range(30):
        if event_path.exists() and sum(1 for _ in event_path.open()) == expected:
            break
        time.sleep(.1)
    result = run_pipeline(manifest, event_path, output / "results", seed=20261112)
    print(json.dumps({"status": "LOOPBACK_SMOKE_ONLY_NOT_RESEARCH_EVIDENCE", "output": str(output),
                      "episodes": result["n_episodes"], "events": result["n_events"]}, indent=2))

if __name__ == "__main__":
    main()
