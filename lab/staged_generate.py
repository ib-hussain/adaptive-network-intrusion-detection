"""Crash-recoverable, bounded, non-destructive multi-stage network scenario generator.

Only communicates with the configured private lab HTTP gateway. The terms
'incident', 'onset', and 'milestone' refer to **controlled behaviour profiles**,
not exploits, infections, exfiltration, or production incidents.

A round consists of a benign and a profile-labelled episode. Both finish before
one atomic round record is committed. Incomplete requests remain in the raw
shared gateway log but are *not* included in the materialised dataset.
"""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import random
import time
import urllib.request
import uuid

from src.code.game import Exp3

POLICIES = ("fixed", "random", "strategic", "test")
TRAIN_PROFILES = ("rapid_repeat", "destination_shift", "jittered_burst")
HELD_OUT_PROFILE = "slow_ramp"
BENIGN_VARIANTS = ("steady", "maintenance_burst", "service_fanout", "approved_bulk")
DEFENCES = ("rate", "spread")
REQUESTS = 20
ONSET_INDEX = 5
ESCALATION_INDEX = 12
MILESTONE_INDEX = 19
SCHEMA_VERSION = "staged_v2_1"


def atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.pending.{os.getpid()}")
    try:
        with tmp.open("x", encoding="utf-8") as fp:
            json.dump(value, fp, allow_nan=False, sort_keys=True, indent=2)
            fp.write("\n")
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def atomic_jsonl(path: Path, records) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.pending.{os.getpid()}")
    try:
        with tmp.open("x", encoding="utf-8") as fp:
            for record in records:
                fp.write(json.dumps(record, sort_keys=True, allow_nan=False) + "\n")
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def episode_schedule(incident: bool, profile: str, benign_variant: str, seed: int, index: int):
    """Return private target, inter-request pause and harmless bytes.

    The warmup is identical for benign/incident episodes with the same seed.
    The final dummy transfer is NOT a malicious payload.
    """
    r = random.Random(seed + index * 17)
    target = "a" if (index % 4) else "b"
    gap = .055 + r.random() * .040
    size = 20 + index % 5 * 19
    if incident and index >= ONSET_INDEX:
        if profile == "rapid_repeat":
            target = "a"; gap = .013 + r.random() * .016
        elif profile == "destination_shift":
            target = "a" if index % 3 == 0 else "b"; gap = .041 + r.random() * .030
        elif profile == "jittered_burst":
            target = "a" if index % 4 else "b"
            gap = (.010 if index % 5 < 3 else .110) + r.random() * .017
        elif profile == HELD_OUT_PROFILE:
            target = "a" if index % 5 else "b"
            gap = max(.012, .13 - .005 * index) + r.random() * .018
        else:
            raise ValueError(f"Unknown staged profile: {profile}")
        # Final stage simulates a separately logged harmless transfer.
        if index == MILESTONE_INDEX:
            target = "b"; size = 2048
    elif not incident and index >= ONSET_INDEX:
        if benign_variant == "maintenance_burst":
            gap = .013 + r.random() * .016 if index % 7 < 3 else .080
        elif benign_variant == "service_fanout":
            target = "a" if index % 2 else "b"
        elif benign_variant == "approved_bulk":
            size = 2048 if index in (8, 16) else size
        elif benign_variant != "steady":
            raise ValueError(f"Unknown benign variant: {benign_variant}")
    return target, gap, b"Z" * size


def emit(base_url, eid, condition, profile, benign_variant, seed, delay_scale):
    if condition not in ("benign", "incident"):
        raise ValueError("Unknown condition")
    is_incident = condition == "incident"
    start_ts = time.time()
    onset_ts = None
    milestone_ts = None
    escalation_ts = None
    gaps, dsts = [], []
    previous_ts = None
    # Ground-truth times originate in the controller, independent of any detector.
    for index in range(REQUESTS):
        if is_incident and index == ONSET_INDEX:
            onset_ts = time.time()
        if is_incident and index == ESCALATION_INDEX:
            escalation_ts = time.time()
        if is_incident and index == MILESTONE_INDEX:
            milestone_ts = time.time()
        dst, gap, body = episode_schedule(is_incident, profile, benign_variant, seed, index)
        req = urllib.request.Request(base_url.rstrip("/") + "/" + dst, data=body,
             headers={"X-Lab-Episode": eid, "Content-Type": "application/octet-stream"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status != 200:
                raise RuntimeError(f"Lab gateway returned HTTP {response.status}")
            response.read()
        observed = time.time()
        if previous_ts is not None:
            gaps.append(observed - previous_ts)
        dsts.append(dst)
        previous_ts = observed
        if index < REQUESTS - 1:
            time.sleep(gap * delay_scale)
    end_ts = time.time()
    if is_incident and not start_ts < onset_ts < escalation_ts < milestone_ts < end_ts:
        raise ValueError("Incident stage timestamps invalid; do not publish round")
    record = dict(episode_id=eid, condition=condition,
            profile=profile if is_incident else benign_variant,
            start_ts=start_ts, onset_ts=onset_ts, escalation_ts=escalation_ts,
            milestone_ts=milestone_ts, end_ts=end_ts, requests=REQUESTS,
            topology="docker_two_internal_segments_two_services",
            scenario_schema=SCHEMA_VERSION,
            milestone_type="simulated_dummy_transfer_to_service_b" if is_incident else None,
            ground_truth="controller_observed_HTTP_success", source_format="gateway_requests",
            note="Authorised harmless request patterns only; NOT actual malware, exploitation or data loss")
    return record, gaps, dsts


def game_reward(profile, defence, gaps, dsts):
    if defence not in DEFENCES or profile not in TRAIN_PROFILES:
        raise ValueError("Invalid game action")
    detected = (min(gaps) < .032) if defence == "rate" else len(set(dsts)) >= 2
    costs = {"rapid_repeat": .16, "destination_shift": .12, "jittered_burst": .10}
    attacker = max(0., min(1., (.90 if not detected else .10) - costs[profile]))
    defender = .90 if detected else .10
    return detected, attacker, defender


def _bundle_path(root: Path, policy: str, round_idx: int) -> Path:
    return root / "rounds" / f"{policy}_{round_idx:04d}.json"


def _rebuild_outputs(root: Path, budgets: dict):
    episodes, game = [], []
    complete = True
    for policy in POLICIES:
        for j in range(budgets[policy]):
            path = _bundle_path(root, policy, j)
            if not path.is_file():
                complete = False
                continue
            bundle = json.loads(path.read_text(encoding="utf-8"))
            if bundle.get("policy") != policy or bundle.get("round") != j:
                raise ValueError(f"Corrupted round bundle {path}")
            episodes.extend((bundle["benign"], bundle["incident"]))
            if policy != "test":
                game.append({k: bundle[k] for k in ("policy", "round", "profile", "defence", "detected",
                                                              "attacker_reward", "defender_reward")})
    episodes.sort(key=lambda e: e["start_ts"])
    atomic_jsonl(root / "episodes.jsonl", episodes)
    atomic_jsonl(root / "game_rounds.jsonl", game)
    if complete:
        atomic_json(root / "complete.json", {"schema": SCHEMA_VERSION,
            "episodes": len(episodes), "expected_episodes": 2 * sum(budgets.values()),
            "condition": "HARMLess_CONTROLLED_NETWORK_SCENARIOS_NOT_REAL_INTRUSIONS"})
    return complete, len(episodes)


def run(root, gateway, rounds, test_rounds, seed, delay_scale=1., resume=False, stop_after_rounds=None, init_only=False):
    if rounds < 3 or test_rounds < 3 or rounds > 150 or test_rounds > 150:
        raise ValueError("Budget must be 3..150 rounds per policy")
    if not .01 <= delay_scale <= 5:
        raise ValueError("Delay scale out of bounds")
    root = Path(root)
    budget = {"fixed": rounds, "random": rounds, "strategic": rounds, "test": test_rounds}
    config = dict(schema=SCHEMA_VERSION, rounds=rounds, test_rounds=test_rounds,
                  seed=seed, requests=REQUESTS, train_profiles=list(TRAIN_PROFILES),
                  held_out_profile=HELD_OUT_PROFILE, delay_scale=delay_scale,
                  topology="docker_two_internal_segments_two_services")
    conf_path = root / "scenario_config.json"
    if resume:
        if not conf_path.is_file():
            raise FileNotFoundError("Cannot resume without existing scenario_config.json")
        if json.loads(conf_path.read_text(encoding="utf-8")) != config:
            raise ValueError("Resume configuration differs; refusing unsafe continuation")
    else:
        if root.exists():
            raise FileExistsError("Refusing to replace an existing run directory. Use --resume for an existing run")
        root.mkdir(parents=True)
        atomic_json(conf_path, config)
    if init_only:
        return {"initialised": True, "run_dir": str(root), "episode_budget": 2 * sum(budget.values())}
    # Full round records are the authoritative checkpoint, never the intermediate append log.
    completed_new = 0
    for policy in POLICIES:
        attacker = Exp3(TRAIN_PROFILES, seed + 31)
        defender = Exp3(DEFENCES, seed + 71)
        for j in range(budget[policy]):
            profile = (
                TRAIN_PROFILES[j % len(TRAIN_PROFILES)] if policy == "fixed" else
                random.Random(seed + j * 719 + 1).choice(TRAIN_PROFILES) if policy == "random" else
                HELD_OUT_PROFILE if policy == "test" else attacker.choose())
            defence = defender.choose() if policy == "strategic" else "rate"
            dest = _bundle_path(root, policy, j)
            if dest.is_file():
                saved = json.loads(dest.read_text(encoding="utf-8"))
                if saved.get("profile") != profile or saved.get("defence") != defence:
                    raise ValueError(f"Replay mismatch in {dest}; strategy has diverged")
                if policy == "strategic":
                    attacker.observe(float(saved["attacker_reward"]))
                    defender.observe(float(saved["defender_reward"]))
                continue
            idprefix = f"v2-{policy}-{j}-{uuid.uuid4().hex[:12]}"
            benign_variant = BENIGN_VARIANTS[(j + seed) % len(BENIGN_VARIANTS)]
            local_seed = seed + j * 13 + POLICIES.index(policy) * 104729
            benign, _, _ = emit(gateway, idprefix + "-benign", "benign", "steady", benign_variant, local_seed, delay_scale)
            incident, gaps, dsts = emit(gateway, idprefix + "-incident", "incident", profile, benign_variant, local_seed, delay_scale)
            for episode in (benign, incident):
                episode["policy"] = policy
                episode["seed"] = local_seed
            if policy != "test":
                detected, att_reward, def_reward = game_reward(profile, defence, gaps, dsts)
            else:
                detected, att_reward, def_reward = None, None, None
            bundle = dict(schema=SCHEMA_VERSION, policy=policy, round=j, profile=profile,
                     defence=defence, benign=benign, incident=incident, detected=detected,
                     attacker_reward=att_reward, defender_reward=def_reward)
            atomic_json(dest, bundle)
            if policy == "strategic":
                attacker.observe(att_reward)
                defender.observe(def_reward)
            completed_new += 1
            complete, n = _rebuild_outputs(root, budget)
            print(f"{policy} round {j + 1}/{budget[policy]} committed; {n} complete episodes", flush=True)
            if stop_after_rounds and completed_new >= stop_after_rounds:
                print("INTENTIONAL_PARTIAL_STOP: rerun with --resume", flush=True)
                return {"complete": False, "episodes": n}
    complete, n = _rebuild_outputs(root, budget)
    return {"complete": complete, "episodes": n, "run_dir": str(root)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--gateway", default="http://gateway:8080")
    p.add_argument("--rounds", type=int, default=12)
    p.add_argument("--test-rounds", type=int, default=12)
    p.add_argument("--seed", type=int, default=20261114)
    p.add_argument("--delay-scale", type=float, default=1.)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--init-only", action="store_true", help="Create immutable run config without generating traffic")
    p.add_argument("--stop-after-rounds", type=int, help="Unit/integration testing only: intentional partial stop")
    a = p.parse_args()
    result = run(a.output, a.gateway, a.rounds, a.test_rounds, a.seed, a.delay_scale, a.resume, a.stop_after_rounds, a.init_only)
    print(json.dumps(result, sort_keys=True))

if __name__ == "__main__":
    main()
