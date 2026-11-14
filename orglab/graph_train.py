"""Small causal GraphSAGE+GRU prototype trained on observed ORGLAB gateway communications.

This is a genuine message-passing GNN, but its edges come from the gateway
application log, NOT directly from Zeek conn.log. A Zeek-native graph adapter
and held-out topology experiment remain separate scientific requirements.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from pathlib import Path

from orglab.audit import audit_run, load_jsonl
from orglab.dataset import assign_records
from orglab.train import digest, partition_rows, splits, threshold_from_validation, warning_metrics


def graph_episode(ep: dict, observations: list[dict], nodes: int, lookback: int = 8):
    import numpy as np
    N = nodes + 4  # employee nodes + gateway + docs/crm/mail
    src_gateway = nodes
    features, adjacency, y, kept_ts = [], [], [], []
    services = {"docs": nodes + 1, "crm": nodes + 2, "mail": nodes + 3}
    for j, o in enumerate(observations):
        ts = float(o["ts"])
        if ep["condition"] == "incident" and ts >= float(ep["milestone_ts"]):
            break
        past = observations[max(0, j - lookback + 1):j + 1]
        x = np.zeros((N, 7), dtype="float32")
        a = np.zeros((N, N), dtype="float32")
        x[:nodes, 4] = 1.0
        x[src_gateway, 5] = 1.0
        x[nodes + 1:, 6] = 1.0
        for r in past:
            emp = int(str(r["employee"]).rsplit("_", 1)[1]) - 1
            if emp < 0 or emp >= nodes:
                raise ValueError("unknown employee node")
            sv = services[str(r["service"])]
            for u, v in ((emp, src_gateway), (src_gateway, sv)):
                a[u, v] = 1.0  # true directed edges from seen requests, never future
                x[u, 0] += 1.0 / lookback
                x[v, 1] += 1.0 / lookback
                x[u, 2] += min(int(r["request_bytes"]) / (512 * lookback), 1.0)
                x[v, 3] += min(int(r["request_bytes"]) / (512 * lookback), 1.0)
        features.append(x)
        adjacency.append(a)
        y.append(int(ep["condition"] == "incident" and ts >= ep["onset_ts"]))
        kept_ts.append(ts)
    return {"episode_id": ep["episode_id"], "features": np.stack(features),
            "adjacency": np.stack(adjacency), "labels": np.asarray(y, dtype="float32"),
            "times": kept_ts, "condition": ep["condition"], "policy": ep["policy"], "round": ep["round"]}


def dataset(run: Path):
    eps = load_jsonl(run / "episodes.jsonl")
    gw = load_jsonl(run / "gateway_requests.jsonl")
    nodes = int(eps[0]["nodes"])
    mapping, unmatched = assign_records(eps, gw)
    if unmatched:
        raise ValueError(f"{unmatched} unassigned gateway records: unexpected time contamination")
    data = {ep["episode_id"]: graph_episode(ep, mapping[ep["episode_id"]], nodes) for ep in eps}
    return eps, data, nodes


def get_network():
    import torch
    from torch import nn

    class MeanSAGE(nn.Module):
        def __init__(self, inp, out):
            super().__init__()
            self.linear = nn.Linear(inp * 3, out)

        def forward(self, x, a):
            # x [time,nodes,channels]; a [time,source,destination]
            outgoing = a.sum(2, keepdim=True).clamp(min=1)
            incoming = a.sum(1, keepdim=True).transpose(1, 2).clamp(min=1)
            out_agg = torch.bmm(a, x) / outgoing
            in_agg = torch.bmm(a.transpose(1, 2), x) / incoming
            return torch.relu(self.linear(torch.cat((x, out_agg, in_agg), -1)))

    class CausalGraphGRU(nn.Module):
        def __init__(self):
            super().__init__()
            self.sage1 = MeanSAGE(7, 32)
            self.sage2 = MeanSAGE(32, 32)
            self.recurrent = nn.GRU(64, 48, batch_first=True)
            self.classifier = nn.Linear(48, 1)

        def forward(self, x, a):
            z = self.sage2(self.sage1(x, a), a)
            pooled = torch.cat((z.mean(1), z.max(1).values), 1)
            seq, _ = self.recurrent(pooled.unsqueeze(0))
            return self.classifier(seq.squeeze(0)).squeeze(1)

    return CausalGraphGRU()


def forward_episode(net, e: dict, device):
    import torch
    x = torch.as_tensor(e["features"], device=device)
    a = torch.as_tensor(e["adjacency"], device=device)
    y = torch.as_tensor(e["labels"], device=device)
    return net(x, a), y


def score_episodes(net, episodes: list[dict], device):
    import torch
    rows, scores = [], []
    net.eval()
    with torch.no_grad():
        for ep in episodes:
            logits, y = forward_episode(net, ep, device)
            s = torch.sigmoid(logits).cpu().tolist()
            for ts, label, score in zip(ep["times"], y.cpu().tolist(), s):
                rows.append({"episode_id": ep["episode_id"], "ts": ts, "label": int(label)})
                scores.append(float(score))
    return rows, scores


def train_graph(run: Path, out: Path, policy: str, epochs: int, resume: bool, device_name: str,
                persistence: int, alpha: float):
    import numpy as np
    import torch
    from torch import nn
    from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

    if epochs < 1 or epochs > 1000:
        raise ValueError("epochs outside permitted range")
    audit_run(run, live=False, min_packets=4)
    sensor_path = run / "zeek_audit.json"
    if not sensor_path.exists() or json.loads(sensor_path.read_text())["status"] != "PASS":
        raise ValueError("Zeek capture+episode alignment gate required for GPU training")
    eps, graphs, nodes = dataset(run)
    parts = splits(eps, policy)
    datasets = {k: [graphs[e["episode_id"]] for e in part] for k, part in parts.items()}
    identity = {"manifest_sha256": digest(run / "episodes.jsonl"),
                "gateway_sha256": digest(run / "gateway_requests.jsonl"),
                "policy": policy, "nodes": nodes, "feature_spec": "orglab_graph_v1",
                "architecture": "two directed MeanSAGE layers + causal GRU"}
    device = torch.device("cuda" if device_name == "auto" and torch.cuda.is_available() else
                          "cpu" if device_name == "auto" else device_name)
    random.seed(20261114)
    np.random.seed(20261114)
    torch.manual_seed(20261114)
    net = get_network().to(device)
    optim = torch.optim.AdamW(net.parameters(), lr=0.001, weight_decay=1e-4)
    objective = nn.BCEWithLogitsLoss()
    checkpoint = out / "latest.pt"
    start = 0
    best_val_loss = float("inf")
    best_epoch = 0
    if resume:
        if not checkpoint.exists():
            raise FileNotFoundError("--resume requested but latest.pt absent")
        # Checkpoint loaded only from own trusted experiment directory.
        saved = torch.load(checkpoint, map_location="cpu", weights_only=True)
        if saved["identity"] != identity:
            raise ValueError("dataset/source identity changed, refusing mismatched resume")
        net.load_state_dict(saved["model"])
        optim.load_state_dict(saved["optim"])
        torch.set_rng_state(saved["cpu_rng"])
        if device.type == "cuda" and saved.get("cuda_rng") is not None:
            torch.cuda.set_rng_state_all(saved["cuda_rng"])
        start = int(saved["epoch"])
        best_val_loss = float(saved.get("best_val_loss", float("inf")))
        best_epoch = int(saved.get("best_epoch", 0))
        print(f"RESUMED policy={policy} epoch={start} device={device}", flush=True)
    else:
        out.mkdir(parents=True, exist_ok=False)
    print(f"GRAPH_TRAIN_START policy={policy} device={device} nodes={nodes} "
          f"train_ep={len(datasets['train'])} val_ep={len(datasets['validation'])} epochs={epochs}", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    for epoch in range(start, epochs):
        net.train()
        order = list(range(len(datasets["train"])))
        random.shuffle(order)
        loss_total = 0.0
        for ix in order:
            e = datasets["train"][ix]
            logits, y = forward_episode(net, e, device)
            loss = objective(logits, y)
            if not torch.isfinite(loss):
                raise ValueError("non-finite graph loss")
            optim.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(net.parameters(), 1.0)
            optim.step()
            loss_total += float(loss.item())
        net.eval()
        val_loss = 0.0
        with torch.no_grad():
            for e in datasets["validation"]:
                logits, y = forward_episode(net, e, device)
                val_loss += float(objective(logits, y).item())
        val_loss /= len(datasets["validation"])
        is_best = val_loss < best_val_loss
        if is_best:
            best_val_loss, best_epoch = val_loss, epoch + 1
        data = {"epoch": epoch + 1, "model": net.state_dict(), "optim": optim.state_dict(),
                "cpu_rng": torch.get_rng_state(), "cuda_rng": torch.cuda.get_rng_state_all() if device.type == "cuda" else None,
                "identity": identity, "val_loss": val_loss, "best_val_loss": best_val_loss, "best_epoch": best_epoch}
        if is_best:
            best_tmp = out / "best.partial.pt"
            torch.save({"epoch": epoch + 1, "model": net.state_dict(), "identity": identity,
                        "val_loss": val_loss}, best_tmp)
            os.replace(best_tmp, out / "best.pt")
        tmp = out / "latest.partial.pt"
        torch.save(data, tmp)
        os.replace(tmp, checkpoint)
        with (out / "epochs.jsonl").open("a") as f:
            f.write(json.dumps({"epoch": epoch + 1, "train_loss": loss_total / len(order),
                                "val_loss": val_loss}) + "\n")
        print(f"EPOCH {epoch + 1}/{epochs} policy={policy} train_loss={loss_total/len(order):.5f} "
              f"val_loss={val_loss:.5f} checkpoint={checkpoint}", flush=True)
    if (out / "best.pt").exists():
        best_saved = torch.load(out / "best.pt", map_location="cpu", weights_only=True)
        if best_saved["identity"] != identity:
            raise ValueError("best checkpoint identity mismatch")
        net.load_state_dict(best_saved["model"])
    val_rows, val_scores = score_episodes(net, datasets["validation"], device)
    test_rows, test_scores = score_episodes(net, datasets["test"], device)
    threshold = threshold_from_validation(parts["validation"], val_rows, val_scores, alpha, persistence)
    warn = warning_metrics(parts["test"], test_rows, test_scores, threshold, persistence)
    ytest = np.asarray([r["label"] for r in test_rows])
    pred = np.asarray([s >= threshold for s in test_scores], dtype=int)
    if len(set(ytest)) < 2:
        raise ValueError("test lacks two classes")
    metrics = {"policy": policy, "architecture": identity["architecture"], "device": str(device),
               "epochs": epochs, "selected_epoch": best_epoch, "best_val_loss": best_val_loss,
               "threshold": threshold, "persistence": persistence,
               "warning": warn,
               "detection": {"macro_f1": float(f1_score(ytest, pred, average="macro", zero_division=0)),
                             "positive_precision": float(precision_score(ytest, pred, zero_division=0)),
                             "positive_recall": float(recall_score(ytest, pred, zero_division=0)),
                             "pr_auc": float(average_precision_score(ytest, test_scores))},
               "identity": identity, "source": "gateway-observed application relationships; Zeek-native graph pending",
               "caveat": "Benign/controlled unusual HTTP profiles; no verified malware or zero-day"}
    (out / "results.json").write_text(json.dumps(metrics, indent=2) + "\n")
    export_tmp = out / "inference.partial.pt"
    torch.save({"model": net.state_dict(), "identity": identity, "threshold": threshold}, export_tmp)
    os.replace(export_tmp, out / "inference.pt")
    print(f"GRAPH_TRAIN_COMPLETE policy={policy} test_PR_AUC={metrics['detection']['pr_auc']:.3f} "
          f"coverage={warn['warning_coverage']:.3f} output={out}", flush=True)
    return metrics


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run-dir", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--policy", choices=["fixed", "random", "strategic"], required=True)
    p.add_argument("--epochs", type=int, default=30)
    p.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--persistence", type=int, default=2)
    p.add_argument("--max-false-positive-episode-fraction", type=float, default=0.1)
    a = p.parse_args()
    train_graph(a.run_dir, a.output, a.policy, a.epochs, a.resume, a.device,
                a.persistence, a.max_false_positive_episode_fraction)


if __name__ == "__main__":
    main()
