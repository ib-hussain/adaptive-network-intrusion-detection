import json
import struct
from pathlib import Path

import pytest

from orglab.audit import audit_run, count_pcap
from orglab.composegen import build_compose
from orglab.dataset import FEATURES, build_rows
from orglab.runtime import ESCALATION_STEP, MILESTONE_STEP, NUM_STEPS, ONSET_STEP, PROFILES, TEST_PROFILE, task_plan
from orglab.train import splits, threshold_from_validation, warning_metrics


def write_pcap(path: Path, n: int = 5):
    with path.open("wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiiii", 2, 4, 0, 0, 65535, 1))
        for i in range(n):
            frame = b"\x00" * 60
            f.write(struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


def fixture_data(run: Path, rounds=4, test_rounds=2, nodes=20):
    """Synthetic *unit-test fixtures only*; not scientific training or capture evidence."""
    (run / "captures").mkdir(parents=True)
    write_pcap(run / "captures" / "orglab.pcap")
    eps, gateway = [], []
    k = 0
    for policy in ("fixed", "random", "strategic", "test"):
        for rnd in range(test_rounds if policy == "test" else rounds):
            for condition in ("benign", "incident"):
                base = 1000 + k * 50
                k += 1
                ep = {"episode_id": f"e{k}", "policy": policy, "round": rnd,
                      "condition": condition, "profile": TEST_PROFILE if policy == "test" else "rapid_repeat",
                      "start_ts": base, "end_ts": base + 30, "onset_ts": base + 6 if condition == "incident" else None,
                      "escalation_ts": base + 16 if condition == "incident" else None,
                      "milestone_ts": base + 23 if condition == "incident" else None,
                      "requests": 24, "nodes": nodes}
                eps.append(ep)
                for t in range(24):
                    emp = t % nodes + 1
                    if condition == "incident" and t >= 5:
                        emp = 1 if t % 5 else 2
                    gateway.append({"ts": base + 1 + t, "end_ts": base + 1.1 + t,
                                    "source_ip": f"10.10.0.{emp}", "employee": f"employee_{emp:03d}",
                                    "service": ("docs", "crm", "mail")[t % 3], "elapsed": 0.1,
                                    "request_bytes": 128, "probe": False})
    (run / "episodes.jsonl").write_text("".join(json.dumps(e) + "\n" for e in eps))
    (run / "gateway_requests.jsonl").write_text("".join(json.dumps(g) + "\n" for g in gateway))
    (run / "collection_complete.json").write_text(json.dumps({"expected_episodes": len(eps),
                                                                 "expected_gateway_requests": len(gateway)}))
    (run / "zeek_audit.json").write_text('{"status":"PASS","episode_coverage":1.0}')
    return eps, gateway


def test_generated_compose_security_and_fifty_node_scaling():
    for n in (20, 50):
        c = build_compose(n)
        workers = [k for k in c["services"] if k.startswith("employee_")]
        assert len(workers) == n
        assert all(v["internal"] for v in c["networks"].values())
        assert all(not x.get("ports") for x in c["services"].values())
        assert all(not x.get("privileged") for x in c["services"].values())
        assert c["services"]["capture"]["cap_add"] == ["NET_RAW", "SETUID", "SETGID"]
        assert c["services"]["capture"]["network_mode"] == "service:gateway"
        assert c["services"]["gateway"]["networks"] == ["employees_internal", "services_internal"]
        segmented = build_compose(n, "departmental")
        assert len(segmented["networks"]) == 5
        assert all(x["internal"] for x in segmented["networks"].values())
        assert len(segmented["services"]["gateway"]["networks"]) == 5
        assert all(len(segmented["services"][f"employee_{k:03d}"]["networks"]) == 1 for k in range(1, n + 1))
    for bad in (0, 19, 51, 500):
        with pytest.raises(ValueError):
            build_compose(bad)


def test_scenarios_are_bounded_and_hide_incident_labels_from_actions():
    for profile in PROFILES + (TEST_PROFILE,):
        actions = task_plan(profile, incident=True, n=20, seed=321, step_seconds=0.5)
        assert len(actions) == NUM_STEPS
        assert all(a["employee"].startswith("employee_") for a in actions)
        assert all(a["service"] in ("docs", "crm", "mail") for a in actions)
        assert all(set(a) == {"employee", "service", "operation", "bytes", "delay"} for a in actions)
        assert all(a["bytes"] in (128, 256, 512) for a in actions)
        assert all(a["delay"] > 0 for a in actions)
        assert sum(a["bytes"] for a in actions) == 8 * (128 + 256 + 512)
        assert sum(a["delay"] for a in actions) == pytest.approx(NUM_STEPS * 0.5)
    assert ONSET_STEP < ESCALATION_STEP < MILESTONE_STEP < NUM_STEPS


def test_header_only_and_truncated_pcap_rejected(tmp_path):
    (tmp_path / "captures").mkdir()
    p = tmp_path / "captures" / "orglab.pcap"
    write_pcap(p, 0)
    assert count_pcap(p)["packets"] == 0
    with pytest.raises(ValueError, match="header-only"):
        audit_run(tmp_path, live=True, min_packets=4)
    write_pcap(p, 3)
    with p.open("ab") as f:
        f.write(b"\0" * 7)
    with pytest.raises(ValueError, match="truncated"):
        count_pcap(p)
    assert count_pcap(p, live=True)["packets"] == 3


def test_episode_split_causality_and_training_baseline(tmp_path):
    eps, gateway = fixture_data(tmp_path)
    audit = audit_run(tmp_path, live=False, min_packets=4)
    assert audit["episodes"] == len(eps)
    assert audit["unique_worker_ips"] >= 2
    rows, _ = build_rows(eps, gateway)
    assert len(rows) > 0 and all(len(r["features"]) == len(FEATURES) for r in rows)
    by_id = {e["episode_id"]: e for e in eps}
    assert all(r["ts"] < by_id[r["episode_id"]]["milestone_ts"] for r in rows if r["condition"] == "incident")
    assert all(r["label"] == 0 for r in rows if r["condition"] == "benign")
    for policy in ("fixed", "random", "strategic"):
        s = splits(eps, policy)
        assert all(s[k] for k in s)
        assert not ({x["episode_id"] for x in s["train"]} & {x["episode_id"] for x in s["test"]})
    from orglab.train import train_one
    result = train_one(tmp_path, tmp_path / "models_fixed_rf", policy="fixed", algo="rf", alpha=0.1,
                       persistence=2, allow_gateway_only=False)
    assert 0 <= result["detection"]["pr_auc"] <= 1
    assert (tmp_path / "models_fixed_rf" / "model.joblib").exists()


def test_future_event_alert_cannot_count_as_early_warning():
    eps = [{"episode_id": "e1", "condition": "incident", "start_ts": 1,
            "end_ts": 10, "onset_ts": 3, "milestone_ts": 8},
           {"episode_id": "e2", "condition": "benign", "start_ts": 12, "end_ts": 20}]
    rows = [{"episode_id": "e1", "ts": x} for x in (2, 3, 7, 9)] + [{"episode_id": "e2", "ts": 13}]
    scores = [0, 0.9, 0.95, 0.95, 0]
    stat = warning_metrics(eps, rows, scores, threshold=0.8, persistence=2)
    assert stat["warned_incidents"] == 1  # second sustained flag occurs at t=7 < milestone
    assert stat["conditional_mean_lead_s"] == 1


def test_graphsage_gru_cpu_checkpoint_and_real_resume(tmp_path):
    import torch
    from orglab.graph_train import dataset, forward_episode, get_network, train_graph

    torch.set_num_threads(2)
    fixture_data(tmp_path)
    eps, graphs, nodes = dataset(tmp_path)
    assert nodes == 20
    net = get_network()
    episode = graphs[eps[0]["episode_id"]]
    logits, target = forward_episode(net, episode, torch.device("cpu"))
    assert logits.ndim == target.ndim == 1 and len(logits) == len(target)
    assert torch.isfinite(logits).all()
    output = tmp_path / "graph_checkpoints"
    first = train_graph(tmp_path, output, "fixed", 1, False, "cpu", 2, 0.1)
    saved1 = torch.load(output / "latest.pt", weights_only=True)
    assert saved1["epoch"] == 1
    second = train_graph(tmp_path, output, "fixed", 2, True, "cpu", 2, 0.1)
    saved2 = torch.load(output / "latest.pt", weights_only=True)
    assert saved2["epoch"] == 2
    assert (output / "inference.pt").exists()
    assert len((output / "epochs.jsonl").read_text().strip().splitlines()) == 2
