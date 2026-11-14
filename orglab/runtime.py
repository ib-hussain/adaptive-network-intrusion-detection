"""Standard-library runtime for isolated employee, gateway, service and controller nodes.

No external network targets, privileged code, exploits, or malicious payloads.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SERVICES = ("docs", "crm", "mail")
OPERATIONS = ("read", "update", "report", "health")
PROFILES = ("rapid_repeat", "service_fanout", "jitter_burst")
TEST_PROFILE = "slow_ramp"
NUM_STEPS = 24
ONSET_STEP = 5
ESCALATION_STEP = 14
MILESTONE_STEP = 23


def utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[{utc()}] [ORGLAB] {msg}", flush=True)


def atomic_json(path: Path, data: dict) -> None:
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def emit_jsonl(path: Path, row: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def request_json(url: str, body: dict, *, timeout: float = 6.0) -> dict:
    data = json.dumps(body, separators=(",", ":")).encode()
    r = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(r, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected HTTP {response.status} for {url}")
        return json.loads(response.read(65536))


class Handler(BaseHTTPRequestHandler):
    role = ""
    node_name = ""

    def log_message(self, fmt, *args):
        # Avoid a line per request; controller owns progress events.
        return

    def write_json(self, status: int, payload: dict):
        data = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            return self.write_json(200, {"ready": True, "role": self.role, "node": self.node_name})
        return self.write_json(404, {"error": "unknown path"})

    def do_POST(self):
        size_text = self.headers.get("Content-Length", "0")
        try:
            size = int(size_text)
        except ValueError:
            return self.write_json(400, {"error": "invalid body length"})
        if not 0 < size <= 4096:
            return self.write_json(413, {"error": "body outside bounded range"})
        try:
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise ValueError("body must be an object")
            if self.role == "service":
                if self.path not in ("/read", "/update", "/report", "/health"):
                    raise ValueError("unapproved service operation")
                return self.write_json(200, {"ok": True, "service": self.node_name, "count": len(body.get("data", ""))})
            if self.role == "employee":
                if self.path != "/task":
                    raise ValueError("unapproved employee operation")
                dest, op = body.get("service"), body.get("operation")
                if dest not in SERVICES or op not in OPERATIONS:
                    raise ValueError("unapproved service or operation")
                bytes_count = int(body.get("bytes", 128))
                if bytes_count not in (128, 256, 512):
                    raise ValueError("unapproved payload size")
                probe = bool(body.get("probe", False))
                started = time.time()
                answer = request_json(
                    f"http://gateway:8080/{dest}/{op}",
                    {"data": "A" * bytes_count, "employee": self.node_name, "probe": probe},
                )
                return self.write_json(200, {"ok": bool(answer.get("ok")), "employee": self.node_name,
                                             "service": dest, "elapsed": round(time.time() - started, 6)})
            if self.role == "gateway":
                components = self.path.strip("/").split("/")
                if len(components) != 2 or components[0] not in SERVICES or components[1] not in OPERATIONS:
                    raise ValueError("unapproved gateway destination")
                dest, op = components
                started = time.time()
                answer = request_json(f"http://{dest}:8080/{op}", body)
                finished = time.time()
                row = {
                    "ts": started, "end_ts": finished, "source_ip": self.client_address[0],
                    "employee": str(body.get("employee", "")), "service": dest, "operation": op,
                    "request_bytes": len(str(body.get("data", ""))), "elapsed": finished - started,
                    "probe": bool(body.get("probe", False)), "status": 200,
                }
                emit_jsonl(Path("/results/gateway_requests.jsonl"), row)
                return self.write_json(200, {"ok": bool(answer.get("ok"))})
            raise ValueError("unknown role")
        except (ValueError, KeyError, TypeError) as exc:
            return self.write_json(400, {"error": str(exc)})
        except (TimeoutError, OSError, HTTPError, URLError) as exc:
            log(f"ERROR {self.role}/{self.node_name}: {type(exc).__name__}: {exc}")
            return self.write_json(502, {"error": "upstream failure"})


def serve(role: str, name: str) -> None:
    class Local(Handler):
        pass
    Local.role, Local.node_name = role, name
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Local)
    server.daemon_threads = True
    log(f"READY role={role} name={name} port=8080")
    server.serve_forever(poll_interval=0.25)


def task_plan(profile: str, *, incident: bool, n: int, seed: int, step_seconds: float) -> list[dict]:
    """Return only bounded workload actions; never pass labels/profile to employee containers."""
    rng = random.Random(seed)
    actor = rng.randrange(1, n + 1)
    actions = []
    byte_budget = [128, 256, 512] * (NUM_STEPS // 3)
    rng.shuffle(byte_budget)
    department_service = ("crm", "docs", "mail", "crm")
    for idx in range(NUM_STEPS):
        emp = rng.randrange(1, n + 1)
        svc = department_service[(emp - 1) % 4] if rng.random() < 0.55 else rng.choice(SERVICES)
        delay = step_seconds * rng.uniform(0.75, 1.25)
        op = rng.choice(OPERATIONS)
        if incident and idx >= ONSET_STEP:
            if profile == "rapid_repeat" and rng.random() < 0.75:
                emp, svc = actor, "docs"
                delay *= 0.55
            elif profile == "service_fanout" and rng.random() < 0.72:
                emp, svc = actor, SERVICES[idx % len(SERVICES)]
            elif profile == "jitter_burst":
                if rng.random() < 0.65:
                    emp = actor
                delay *= 0.35 if idx % 4 < 3 else 2.0
            elif profile == "slow_ramp" and rng.random() < (0.1 + 0.8 * (idx - ONSET_STEP) / (NUM_STEPS - ONSET_STEP)):
                emp, svc = actor, SERVICES[idx % len(SERVICES)]
        elif not incident and profile == "maintenance_burst" and idx % 5 < 3:
            delay *= 0.60
        elif not incident and profile == "collaboration" and idx % 3 == 0:
            svc = "docs"
        elif not incident and profile == "approved_bulk" and idx % 4 == 0:
            op = "report"
        actions.append({"employee": f"employee_{emp:03d}", "service": svc, "operation": op,
                        "bytes": byte_budget[idx], "delay": max(0.01, delay)})
    # Same experimental request/byte/planned-duration budgets across all policies.
    scaling = (NUM_STEPS * step_seconds) / sum(a["delay"] for a in actions)
    for action in actions:
        action["delay"] *= scaling
    return actions


class HeuristicEXP3:
    """Bounded timing/fanout proxy; NOT feedback from a trained IDS detector."""
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.weights = [1.0] * len(PROFILES)
        self.gamma = 0.2

    def choose(self):
        total = sum(self.weights)
        probs = [(1 - self.gamma) * w / total + self.gamma / len(PROFILES) for w in self.weights]
        x, cumul = self.rng.random(), 0.0
        for j, p in enumerate(probs):
            cumul += p
            if x <= cumul:
                return j, p
        return len(PROFILES) - 1, probs[-1]

    def update(self, choice: int, prob: float, reward: float):
        assert 0 <= reward <= 1
        self.weights[choice] *= math.exp(self.gamma * reward / (len(PROFILES) * prob))


def collect(run_id: str, n: int, rounds: int, test_rounds: int, seed: int, step_seconds: float):
    if not 20 <= n <= 50 or not 1 <= rounds <= 100 or not 1 <= test_rounds <= 100:
        raise ValueError("invalid bounded experimental budget")
    if not 0.05 <= step_seconds <= 8:
        raise ValueError("step_seconds out of range")
    root = Path("/results")
    (root / "rounds").mkdir(parents=True, exist_ok=True)
    start_marker = root / "collection_started.json"
    # Refuse duplicate run ID: even interrupted collection must be reviewed, not overwritten.
    fd = os.open(start_marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"run_id": run_id, "seed": seed, "nodes": n, "rounds": rounds,
                   "test_rounds": test_rounds, "step_seconds": step_seconds, "started": utc()}, f)
        f.write("\n")
    game = HeuristicEXP3(seed ^ 991)
    manifest = root / "episodes.jsonl"
    budgets = {"fixed": rounds, "random": rounds, "strategic": rounds, "test": test_rounds}
    total = 2 * sum(budgets.values())
    completed = 0
    last_heartbeat = time.monotonic()
    rng = random.Random(seed)
    log(f"COLLECTION START run={run_id} nodes={n} episodes={total} tasks={total * NUM_STEPS}")
    for policy, size in budgets.items():
        for rnd in range(size):
            if policy == "fixed":
                profile, prob, selected = PROFILES[rnd % len(PROFILES)], 1.0, None
            elif policy == "random":
                profile, prob, selected = rng.choice(PROFILES), 1 / len(PROFILES), None
            elif policy == "strategic":
                selected, prob = game.choose()
                profile = PROFILES[selected]
            else:
                profile, prob, selected = TEST_PROFILE, 1.0, None
            benign_profile = ("office_steady", "maintenance_burst", "collaboration", "approved_bulk")[rnd % 4]
            episode_rows = []
            for condition, scenario in (("benign", benign_profile), ("incident", profile)):
                episode_id = f"{run_id}-{policy}-{rnd:04d}-{condition}"
                actions = task_plan(scenario, incident=(condition == "incident"), n=n,
                                    seed=seed + 100000 * (rnd + 1) + 1000 * (1 + list(budgets).index(policy)) + (condition == "incident"),
                                    step_seconds=step_seconds)
                started = time.time()
                onset = escalation = milestone = None
                for idx, action in enumerate(actions):
                    if condition == "incident":
                        if idx == ONSET_STEP:
                            onset = time.time()
                        if idx == ESCALATION_STEP:
                            escalation = time.time()
                        if idx == MILESTONE_STEP:
                            milestone = time.time()  # before harmless final marker request
                    result = request_json(f"http://{action['employee']}:8080/task", {
                        "service": action["service"], "operation": action["operation"], "bytes": action["bytes"]
                    })
                    if not result.get("ok"):
                        raise RuntimeError(f"employee operation not acknowledged {episode_id}/{idx}")
                    time.sleep(action["delay"])
                    if time.monotonic() - last_heartbeat > 15:
                        log(f"HEARTBEAT run={run_id} completed_episodes={completed}/{total} current={episode_id} step={idx + 1}/{NUM_STEPS}")
                        last_heartbeat = time.monotonic()
                end = time.time()
                ep = {"episode_id": episode_id, "run_id": run_id, "policy": policy, "round": rnd,
                      "condition": condition, "profile": scenario, "start_ts": started, "end_ts": end,
                      "onset_ts": onset, "escalation_ts": escalation, "milestone_ts": milestone,
                      "requests": NUM_STEPS, "nodes": n, "topology": os.environ.get("ORG_TOPOLOGY", "flat"),
                      "notes": "Harmless anomalous communication; no real attack or exfiltration",
                      "selection_probability": prob, "game_mode": "heuristic_EXP3_not_detector_feedback"}
                episode_rows.append(ep)
                log(f"EPISODE {completed + 1}/{total} {episode_id} duration={end - started:.2f}s")
                completed += 1
            # Commit both paired episodes atomically before emitting read-only materialisation.
            atomic_json(root / "rounds" / f"{policy}_{rnd:04d}.json", {"episodes": episode_rows})
            for ep in episode_rows:
                emit_jsonl(manifest, ep)
            if policy == "strategic":
                # Proxy reward depends on the completed action profile only, not on detector outcomes.
                game.update(selected, prob, {"rapid_repeat": 0.35, "service_fanout": 0.65, "jitter_burst": 0.5}[profile])
            atomic_json(root / "status.json", {"status": "COLLECTING", "completed_episodes": completed,
                                                   "expected_episodes": total, "updated_utc": utc(), "run_id": run_id})
    atomic_json(root / "collection_complete.json", {"completed_episodes": completed,
                                                        "expected_episodes": total, "expected_gateway_requests": total * NUM_STEPS,
                                                        "run_id": run_id, "completed_utc": utc()})
    atomic_json(root / "status.json", {"status": "COLLECTION_COMPLETE_CAPTURE_PENDING_AUDIT", "completed_episodes": completed,
                                           "expected_episodes": total, "updated_utc": utc(), "run_id": run_id})
    log(f"COLLECTION COMPLETE run={run_id} episodes={completed} expected_gateway_requests={total * NUM_STEPS}")


def probe():
    for i in range(1, 5):
        result = request_json(f"http://employee_{i:03d}:8080/task", {
            "service": SERVICES[(i - 1) % 3], "operation": "health", "bytes": 128, "probe": True
        })
        if not result.get("ok"):
            raise RuntimeError("probe response not successful")
    log("CAPTURE_PROBE_HTTP_OK 4; probe messages are not research episodes")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("role", choices=["employee", "service", "gateway", "controller"])
    p.add_argument("--name", default="")
    p.add_argument("--probe", action="store_true")
    args = p.parse_args()
    if args.role != "controller":
        return serve(args.role, args.name or args.role)
    if args.probe:
        return probe()
    collect(os.environ["ORG_RUN_ID"], int(os.environ["ORG_NODES"]),
            int(os.environ["ORG_ROUNDS"]), int(os.environ["ORG_TEST_ROUNDS"]),
            int(os.environ["ORG_SEED"]), float(os.environ["ORG_STEP_SECONDS"]))


if __name__ == "__main__":
    try:
        main()
    except BaseException as exc:
        log(f"FAILED {type(exc).__name__}: {exc}")
        if len(sys.argv) > 1 and sys.argv[1] == "controller" and "--probe" not in sys.argv:
            root = Path("/results")
            if (root / "collection_started.json").exists() and not (root / "collection_complete.json").exists():
                try:
                    previous = json.loads((root / "status.json").read_text()) if (root / "status.json").exists() else {}
                    previous.update({"status": "FAILED_OR_INTERRUPTED", "updated_utc": utc(),
                                     "error": f"{type(exc).__name__}: {exc}"})
                    atomic_json(root / "status.json", previous)
                except OSError:
                    pass
        raise
