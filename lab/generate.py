"""Real HTTP lab traffic: safe behaviour profiles; no exploitation or malicious code."""
import argparse
import json
import random
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

# When run in a Docker container, /app maps the project's lab package.
from lab.http_service import DESTINATIONS


def append_jsonl(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(value, sort_keys=True) + "\n")


def emit_episode(base_url, episode_id, condition, profile, policy, seed, sink, requests=12,
                 delay_scale=1.0, topology="bridge_two_segment_v1"):
    """Record *independent* scenario timing; all requests go to the private test gateway."""
    if requests < 6 or requests > 32:
        raise ValueError("Episode requests must be between 6 and 32")
    if condition not in ("benign", "incident"):
        raise ValueError("Unknown condition")
    rng = random.Random(seed)
    start = time.time()
    stages = []
    gaps, dsts = [], []
    prev = None
    milestone = None
    # Bounded, staged request patterns; final event is an inert lab milestone.
    for i in range(requests):
        if condition == "benign":
            target = "a" if rng.random() < .8 else "b"
            delay = 0.038 + rng.random() * .045
            payload = b"ok"
        elif profile == "paced":
            target = "a"
            delay = 0.065 + rng.random() * .020
            payload = b"ping"
        elif profile == "bursty":
            target = "a"
            delay = 0.006 + rng.random() * .007
            payload = b"ping"
        elif profile == "fanout":
            target = "a" if i % 2 == 0 else "b"
            delay = 0.026 + rng.random() * .026
            payload = b"ping"
        else:
            raise ValueError(f"Unknown profile {profile}")
        # Fixed milestone index; only inert dummy bytes are transmitted.
        is_milestone = condition == "incident" and i == requests - 1
        if is_milestone:
            payload = b"X" * 2048
            milestone = time.time()
        request = urllib.request.Request(base_url.rstrip("/") + "/" + target, data=payload,
                                         headers={"X-Lab-Episode": episode_id}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=4) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Lab HTTP status {resp.status}")
                resp.read()
        except urllib.error.URLError as exc:
            raise RuntimeError("Lab gateway unavailable; do not log a successful episode") from exc
        now = time.time()
        if prev is not None:
            gaps.append(now - prev)
        prev = now
        dsts.append(target)
        stages.append({"event_index": i, "time": now, "destination": target, "milestone": is_milestone})
        if i < requests - 1:
            time.sleep(delay * delay_scale)
    end = time.time()
    record = {"episode_id": episode_id, "condition": condition, "profile": profile if condition == "incident" else "normal",
              "policy": policy, "seed": seed, "topology": topology, "start_ts": start,
              "onset_ts": start if condition == "incident" else None, "milestone_ts": milestone,
              "end_ts": end, "requests": requests, "ground_truth": "scenario_controller",
              "source_format": "gateway_requests", "note": "Controlled non-malicious application traffic; incident is scenario label"}
    append_jsonl(sink, record)
    return record, gaps, dsts


def run(output, gateway, episodes=12, test_episodes=12, seed=20261112, delay_scale=1.0):
    from src.code.game import Exp3, PROFILES, DEFENCES, payoff
    out = Path(output)
    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "episodes.jsonl"
    game_path = out / "game_rounds.jsonl"
    if manifest_path.exists() or game_path.exists():
        raise FileExistsError("Existing experiment log present. Choose a new empty output directory; no overwriting.")
    rng = random.Random(seed)
    # Each collection policy receives identical episode budgets. Test set is never fed back to either agent.
    for policy in ("fixed", "random", "strategic", "test"):
        n = test_episodes if policy == "test" else episodes
        attacker = Exp3(PROFILES, seed + 11)
        defender = Exp3(DEFENCES, seed + 22)
        for j in range(n):
            profile = PROFILES[j % len(PROFILES)] if policy == "fixed" else (rng.choice(PROFILES) if policy in ("random", "test") else attacker.choose())
            defence = defender.choose() if policy == "strategic" else "rate"
            eid = f"{policy}-{j}-{uuid.uuid4().hex[:10]}"
            # Benign case is independently recorded; exclude its traces from strategy feedback.
            emit_episode(gateway, eid + "-normal", "benign", "normal", policy, seed + j * 100 + 1, manifest_path,
                         delay_scale=delay_scale)
            record, gaps, dsts = emit_episode(gateway, eid + "-incident", "incident", profile, policy, seed + j * 100 + 2,
                                             manifest_path, delay_scale=delay_scale)
            if policy != "test":
                result = payoff(profile, defence, gaps, dsts)
                append_jsonl(game_path, {"round": j, "policy": policy, "episode_id": record["episode_id"],
                                         "profile": profile, "reference_defence": defence,
                                         "reference_detected": result.detected_by_reference,
                                         "attacker_reward": result.attacker_reward,
                                         "defender_reward": result.defender_reward})
                if policy == "strategic":
                    attacker.observe(result.attacker_reward)
                    defender.observe(result.defender_reward)
    return manifest_path


def main():
    p = argparse.ArgumentParser(description="Generate bounded research traffic only")
    p.add_argument("--output", required=True)
    p.add_argument("--gateway", default="http://gateway:8080")
    p.add_argument("--episodes", type=int, default=12)
    p.add_argument("--test-episodes", type=int, default=12)
    p.add_argument("--seed", type=int, default=20261112)
    p.add_argument("--delay-scale", type=float, default=1.0)
    a = p.parse_args()
    if not 1 <= a.episodes <= 200 or not 1 <= a.test_episodes <= 200 or not 0.25 <= a.delay_scale <= 5:
        p.error("Episode counts 1-200; delay-scale 0.25-5")
    print(run(a.output, a.gateway, a.episodes, a.test_episodes, a.seed, a.delay_scale))

if __name__ == "__main__":
    main()
