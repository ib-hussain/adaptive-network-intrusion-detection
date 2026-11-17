"""GNN training using actual Zeek conn.log from cpu_v3_main_v2 run."""
import json
import csv
import sys
import random
from pathlib import Path
from collections import defaultdict

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GATConv
from torch_geometric.data import Data
from sklearn.metrics import average_precision_score, roc_auc_score

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {DEVICE}")

# Load the processed windows
STUDY_DIR = Path("outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z")
with open(STUDY_DIR / "dataset" / "windows.csv") as f:
    reader = csv.DictReader(f)
    windows = list(reader)

# Load split manifest
split_of = {}
with open(STUDY_DIR / "dataset" / "split_manifest.jsonl") as f:
    for line in f:
        row = json.loads(line)
        split_of[row["episode_id"]] = row["split"]

# Load Zeek conn.log from the cpu_v3_main_v2 audit (repaired_strict_000)
ZEEK_CONN = Path("outputs/audits/cpu_v3_main_v2_20261115T164430Z/zeek/repaired_strict_000/conn.log")

print("Parsing Zeek conn.log (JSONL)...")
conn_events = []
with open(ZEEK_CONN) as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                conn_events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

print(f"Parsed {len(conn_events)} connection events")

# Load the manifest from the study (which should match the episodes)
with open(STUDY_DIR / "dataset" / "dataset_manifest.json") as f:
    dataset_manifest = json.load(f)

# The episodes in dataset_manifest should have timing info
episodes = dataset_manifest.get("episodes", [])
print(f"Episodes in dataset manifest: {len(episodes)}")

# Build episode time ranges from dataset manifest
episode_ranges = {}
for ep in episodes:
    episode_ranges[ep["episode_id"]] = (float(ep["start_ts"]), float(ep["end_ts"]))

# Assign each conn event to an episode by timestamp
episode_conns = defaultdict(list)
for conn in conn_events:
    ts = float(conn.get("ts", 0))
    for eid, (start, end) in episode_ranges.items():
        if start <= ts <= end:
            episode_conns[eid].append(conn)
            break

print(f"Episodes with conn data: {len(episode_conns)}")
for eid, conns in list(episode_conns.items())[:5]:
    print(f"  {eid}: {len(conns)} connections")

# Build graphs from actual connection data
def build_graph_from_connections(eid, conns):
    hosts = set()
    for c in conns:
        hosts.add(c.get("id.orig_h", ""))
        hosts.add(c.get("id.resp_h", ""))
    
    host_list = sorted(list(hosts))
    host_to_idx = {h: i for i, h in enumerate(host_list)}
    n_nodes = len(host_list)
    
    if n_nodes == 0:
        return None
    
    node_feat = np.zeros((n_nodes, 4), dtype=np.float32)
    edge_dict = defaultdict(lambda: {"dur": 0.0, "count": 0, "orig_bytes": 0.0, "resp_bytes": 0.0})
    
    for c in conns:
        src = c.get("id.orig_h", "")
        dst = c.get("id.resp_h", "")
        if src in host_to_idx and dst in host_to_idx:
            si = host_to_idx[src]
            di = host_to_idx[dst]
            dur = float(c.get("duration", 0) or 0)
            ob = float(c.get("orig_bytes", 0) or 0)
            rb = float(c.get("resp_bytes", 0) or 0)
            
            node_feat[si, 0] += ob
            node_feat[si, 1] += rb
            node_feat[si, 2] += 1
            node_feat[si, 3] += dur
            
            node_feat[di, 0] += ob
            node_feat[di, 1] += rb
            node_feat[di, 2] += 1
            node_feat[di, 3] += dur
            
            key = (si, di)
            edge_dict[key]["dur"] += dur
            edge_dict[key]["count"] += 1
            edge_dict[key]["orig_bytes"] += ob
            edge_dict[key]["resp_bytes"] += rb
    
    for i in range(4):
        if node_feat[:, i].max() > 0:
            node_feat[:, i] = np.log1p(node_feat[:, i])
    
    edge_list = []
    edge_attrs = []
    for (si, di), attrs in edge_dict.items():
        edge_list.append([si, di])
        edge_attrs.append([
            np.log1p(attrs["dur"]),
            np.log1p(attrs["count"]),
            np.log1p(attrs["orig_bytes"]),
            np.log1p(attrs["resp_bytes"])
        ])
    
    if not edge_list:
        edge_list = [[i, i] for i in range(n_nodes)]
        edge_attrs = [[0, 0, 0, 0] for _ in range(n_nodes)]
    
    x = torch.tensor(node_feat, dtype=torch.float32)
    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    edge_attr = torch.tensor(edge_attrs, dtype=torch.float32)
    
    return Data(x=x, edge_index=edge_index, edge_attr=edge_attr, num_nodes=n_nodes, episode_id=eid)

# Build graphs for train/test episodes
print("\nBuilding graphs from Zeek data...")
train_eids = [eid for eid in episode_conns if split_of.get(eid) == "train"]
val_eids = [eid for eid in episode_conns if split_of.get(eid) == "validation"]
test_eids = [eid for eid in episode_conns if split_of.get(eid) == "test"]

print(f"Train episodes: {len(train_eids)}, Val: {len(val_eids)}, Test: {len(test_eids)}")

train_graphs = []
train_labels = []
for eid in train_eids:
    g = build_graph_from_connections(eid, episode_conns[eid])
    if g is not None:
        ep_windows = [w for w in windows if w["episode_id"] == eid]
        if ep_windows:
            label = int(ep_windows[0]["label"])
            train_graphs.append(g)
            train_labels.append(label)

val_graphs = []
val_labels = []
for eid in val_eids:
    g = build_graph_from_connections(eid, episode_conns[eid])
    if g is not None:
        ep_windows = [w for w in windows if w["episode_id"] == eid]
        if ep_windows:
            label = int(ep_windows[0]["label"])
            val_graphs.append(g)
            val_labels.append(label)

test_graphs = []
test_labels = []
for eid in test_eids:
    g = build_graph_from_connections(eid, episode_conns[eid])
    if g is not None:
        ep_windows = [w for w in windows if w["episode_id"] == eid]
        if ep_windows:
            label = int(ep_windows[0]["label"])
            test_graphs.append(g)
            test_labels.append(label)

print(f"Train graphs: {len(train_graphs)}, Val: {len(val_graphs)}, Test: {len(test_graphs)}")
if train_graphs:
    print(f"  Train labels: {np.bincount(train_labels)}")
    print(f"  Val labels: {np.bincount(val_labels)}")
    print(f"  Test labels: {np.bincount(test_labels)}")
    print(f"  Sample graph: {train_graphs[0].num_nodes} nodes, {train_graphs[0].edge_index.shape[1]} edges, {train_graphs[0].x.shape[1]} features")

# Train GNN if we have data
if len(train_graphs) > 10 and len(test_graphs) > 2:
    class GNNClassifier(nn.Module):
        def __init__(self, node_features, hidden_dim=32, model_type="sage"):
            super().__init__()
            self.model_type = model_type
            if model_type == "sage":
                self.conv1 = SAGEConv(node_features, hidden_dim)
                self.conv2 = SAGEConv(hidden_dim, hidden_dim)
                self.conv3 = SAGEConv(hidden_dim, hidden_dim)
                self.readout = nn.Linear(hidden_dim, 2)
            elif model_type == "gat":
                self.conv1 = GATConv(node_features, hidden_dim, heads=4, dropout=0.5)
                self.conv2 = GATConv(hidden_dim * 4, hidden_dim, heads=4, dropout=0.5, concat=True)
                self.conv3 = GATConv(hidden_dim * 4, hidden_dim, heads=4, dropout=0.5, concat=True)
                self.readout = nn.Linear(hidden_dim * 4, 2)
            self.dropout = 0.5
        def forward(self, data):
            x, ei = data.x, data.edge_index
            for conv in [self.conv1, self.conv2, self.conv3]:
                x = conv(x, ei)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
            x = torch.mean(x, dim=0)
            return self.readout(x)
    
    def train_gnn(model, graphs, labels, epochs=50, lr=0.005):
        model.to(DEVICE)
        model.train()
        optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
        criterion = nn.CrossEntropyLoss()
        for epoch in range(1, epochs + 1):
            loss_sum = 0
            paired = list(zip(graphs, labels))
            random.shuffle(paired)
            for g, lbl in paired:
                g = g.to(DEVICE)
                optimizer.zero_grad()
                out = model(g)
                t = torch.tensor(lbl, dtype=torch.long, device=DEVICE)
                loss = criterion(out, t)
                loss.backward()
                optimizer.step()
                loss_sum += loss.item()
            if epoch % 10 == 0:
                print(f"  Epoch {epoch}/{epochs}, loss={loss_sum/len(graphs):.4f}")
        return model
    
    n_features = train_graphs[0].x.shape[1]
    print(f"\nTraining GraphSAGE with {n_features} node features...")
    sage = GNNClassifier(n_features, model_type="sage").to(DEVICE)
    sage = train_gnn(sage, train_graphs, train_labels, epochs=50, lr=0.005)
    
    print("\nTraining GAT...")
    gat = GNNClassifier(n_features, model_type="gat").to(DEVICE)
    gat = train_gnn(gat, train_graphs, train_labels, epochs=50, lr=0.005)
    
    # Evaluate
    sage.eval()
    gat.eval()
    sage_scores, gat_scores = [], []
    sage_labels, gat_labels = [], []
    
    with torch.no_grad():
        for g, lbl in zip(test_graphs, test_labels):
            g = g.to(DEVICE)
            sage_out = sage(g)
            gat_out = gat(g)
            sage_scores.append(float(sage_out[1].item()))
            gat_scores.append(float(gat_out[1].item()))
            sage_labels.append(lbl)
            gat_labels.append(lbl)
    
    sage_pr_auc = average_precision_score(np.array(sage_labels), np.array(sage_scores))
    gat_pr_auc = average_precision_score(np.array(gat_labels), np.array(gat_scores))
    sage_roc_auc = roc_auc_score(np.array(sage_labels), np.array(sage_scores))
    gat_roc_auc = roc_auc_score(np.array(gat_labels), np.array(gat_scores))
    
    print(f"\n=== Zeek-based GNN Results (cpu_v3_main_v2) ===")
    print(f"GraphSAGE: PR-AUC={sage_pr_auc:.4f}, ROC-AUC={sage_roc_auc:.4f}")
    print(f"GAT: PR-AUC={gat_pr_auc:.4f}, ROC-AUC={gat_roc_auc:.4f}")
    
    # Save results
    out = {
        "graph_type": "zeek_conn_based_cpu_v3",
        "train_graphs": len(train_graphs),
        "val_graphs": len(val_graphs),
        "test_graphs": len(test_graphs),
        "node_features": n_features,
        "graph_sage": {"pr_auc": float(sage_pr_auc), "roc_auc": float(sage_roc_auc)},
        "gat": {"pr_auc": float(gat_pr_auc), "roc_auc": float(gat_roc_auc)},
    }
    
    Path("outputs/gnn_zeek_results_v2").mkdir(parents=True, exist_ok=True)
    with open("outputs/gnn_zeek_results_v2/gnn_zeek_results.json", "w") as f:
        json.dump(out, f, indent=2)
    print("Saved to outputs/gnn_zeek_results_v2/gnn_zeek_results.json")
else:
    print("Not enough graph data for training")

