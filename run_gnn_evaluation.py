"""Extremely minimal GNN evaluation - subset of 200 windows."""
from __future__ import annotations

import csv
import json
import sys
from sklearn.metrics import average_precision_score
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GATConv
from torch_geometric.data import Data

from src.code.features import FEATURE_COLUMNS
from src.code.gnn_baseline import construct_graph_from_window, train_gnn_model

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {DEVICE}")

def construct_graph_from_window_features(wn):
    n_nodes = 8
    node_feature_names = ["event_count", "rate_per_s", "bytes_mean", "unique_links"]
    x = []
    for i in range(n_nodes):
        row = []
        for fn in node_feature_names:
            val = float(wn.get(fn, 0.0))
            if fn == "rate_per_s": val += (i - 3) * 0.1
            elif fn == "unique_links": val += (i % 2)
            row.append(val)
        x.append(row)
    x = torch.tensor(x, dtype=torch.float32)
    edge_pairs = [(a, b) for a in range(n_nodes) for b in range(n_nodes) if a != b]
    edge_index = torch.tensor([[e[0], e[1]] for e in edge_pairs], dtype=torch.long).t().contiguous()
    dur = float(wn.get("duration_mean_s", 0.001))
    tcp_f = float(wn.get("tcp_fraction", 1.0))
    edge_attr = torch.tensor([[dur, tcp_f] for _ in edge_pairs], dtype=torch.float32)
    return Data(x=x, edge_index=edge_index, edge_attr=edge_attr, num_nodes=n_nodes)

class GNNClassifier(nn.Module):
    def __init__(self, node_features=4, hidden_dim=16, model_type="sage"):
        super().__init__()
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

def main():
    windows_path = Path("outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z/dataset/windows.csv")
    with open(windows_path) as f:
        reader = csv.DictReader(f)
        windows = list(reader)
    
    print(f"Loaded {len(windows)} windows")
    
    # Take only 200 windows max
    windows = windows[:200]
    
    # Construct graphs
    graphs = [construct_graph_from_window(w) for w in windows]
    train_graphs = graphs[:160]
    test_graphs = graphs[160:]
    
    train_labels = [1 if w["condition"]=="incident" else 0 for w in windows[:160]]
    test_labels = [1 if w["condition"]=="incident" else 0 for w in windows[160:]]
    
    print(f"Train: {len(train_graphs)} graphs ({sum(train_labels)} incident)")
    print(f"Test:  {len(test_graphs)} graphs ({sum(test_labels)} incident)")
    
    # Train GraphSAGE
    sage = GNNClassifier(model_type="sage").to(DEVICE)
    sage_model = train_gnn_model(sage, train_graphs, train_labels, epochs=5, lr=0.01)
    
    # Train GAT
    gnn = GNNClassifier(model_type="gat").to(DEVICE)
    optimizer = torch.optim.Adam(gnn.parameters(), lr=0.01)
    criterion = nn.CrossEntropyLoss()
    gnn.train()
    for epoch in range(5):
        loss_sum = 0
        for g, lbl in zip(train_graphs, train_labels):
            g = g.to(DEVICE)
            optimizer.zero_grad()
            out = gnn(g)
            t = torch.tensor(lbl, dtype=torch.long, device=DEVICE)
            loss = criterion(out, t)
            loss.backward()
            optimizer.step()
            loss_sum += loss.item()
        print(f"  GAT epoch {epoch+1}/5, loss={loss_sum/len(train_graphs):.4f}")
    
    # Evaluate
    sage_model.eval()
    gnn.eval()
    sage_s, gnn_s, sage_l, gnn_l = [], [], [], []
    with torch.no_grad():
        for g, lbl in zip(test_graphs, test_labels):
            g = g.to(DEVICE)
            sage_s.append(float(sage_model(g)[1].item()))
            gnn_s.append(float(gnn(g)[1].item()))
            sage_l.append(lbl)
            gnn_l.append(lbl)
    
    sage_auc = float(average_precision_score(np.array(sage_l), np.array(sage_s)))
    gnn_auc = float(average_precision_score(np.array(gnn_l), np.array(gnn_s)))
    
    print(f"\nGraphSAGE PR-AUC: {sage_auc:.4f}")
    print(f"GAT PR-AUC: {gnn_auc:.4f}")
    
    out = {
        "sage_pr_auc": sage_auc,
        "gat_pr_auc": gnn_auc,
        "n_train": len(train_graphs),
        "n_test": len(test_graphs),
    }
    Path("outputs/gnn_evaluation/gnn_evaluation.json").parent.mkdir(parents=True, exist_ok=True)
    with open("outputs/gnn_evaluation/gnn_evaluation.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"Saved to outputs/gnn_evaluation/gnn_evaluation.json")

main()
