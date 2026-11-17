"""GNN baselines for staged network intrusion detection.

Constructs host-level graphs from Zeek connection windows and evaluates
GraphSAGE and GAT models for episode-level incident classification.

Graph construction per window (8 observations):
  - Nodes: distinct (src_host, dst_host) pairs observed in the window
  - Node features: mean origin bytes, mean response bytes, duration, rate
  - Edges: directed from src_host -> dst_host (complete graph on observed pairs)
  - Edge features: duration, tcp_fraction (per edge if multiple observations)

Readout: attention-based readout (GAT) or mean pooling (GraphSAGE)
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import List, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GATConv
from torch_geometric.data import Data

from .features import FEATURE_COLUMNS


def construct_graph_from_window(window_row: dict, source_events: List[dict] | None = None) -> Data:
    """Construct a PyG Data graph from a single window's observations.

    Args:
        window_row: Dict from windows.csv with episode_id, features, timestamps
        source_events: List of raw event dicts with per-event detail (src_host, dst_host,
                       orig_bytes, resp_bytes, duration, proto, ts). If None, features are
                       derived from the window_row values only.

    Returns:
        pyg.data.Data object with node features, edge indices, and edge features.
    """
    # Determine nodes: unique (src_host, dst_host) pairs
    # In the staged data, each window has 8 observations; we build one graph per window
    src_hosts = []
    dst_hosts = []
    orig_bytes_list = []
    resp_bytes_list = []
    duration_list = []
    proto_list = []

    if source_events is not None:
        for ev in source_events:
            src_hosts.append(ev.get("src_host", "host_0"))
            dst_hosts.append(ev.get("dst_host", "host_1"))
            orig_bytes_list.append(float(ev.get("orig_bytes", 0)))
            resp_bytes_list.append(float(ev.get("resp_bytes", 0)))
            duration_list.append(float(ev.get("duration", 0)))
            proto_list.append(ev.get("proto", "tcp"))
    else:
        # Fallback: use window-level features to synthesize node features
        # This is a simplified approach; real data would have per-event detail
        n_nodes = 3  # typical unique_links count
        src_hosts = [f"h{i}" for i in range(n_nodes)]
        dst_hosts = [f"h{(i+1)%n_nodes}" for i in range(n_nodes)]
        # Distribute bytes_mean across nodes
        total_bytes = float(window_row.get("bytes_mean", 0) or 0)
        orig_bytes_list = [total_bytes * 0.3, total_bytes * 0.3, total_bytes * 0.4]
        resp_bytes_list = [total_bytes * 0.1, total_bytes * 0.1, total_bytes * 0.2]
        duration_list = [float(window_row.get("duration_mean_s", 0) or 0)] * n_nodes
        proto_list = ["tcp"] * n_nodes

    n_nodes = len(src_hosts)

    # Node features: [orig_bytes_mean, resp_bytes_mean, duration_mean_s, rate_per_s]
    # We compute simple per-node stats from the distribution
    node_features = []
    for i in range(n_nodes):
        ob = orig_bytes_list[i] if i < len(orig_bytes_list) else 0.0
        rb = resp_bytes_list[i] if i < len(resp_bytes_list) else 0.0
        dt = duration_list[i] if i < len(duration_list) else 0.0
        # rate approximated as bytes / duration if duration > 0
        rate = ob / dt if dt > 0 else 0.0
        node_features.append([ob, rb, dt, rate])

    x = torch.tensor(node_features, dtype=torch.float32)

    # Edge index: complete directed graph (including self-loops omitted for simplicity)
    # Edge features: [duration, tcp_fraction] per edge
    edge_list = []
    edge_features = []
    for i in range(n_nodes):
        for j in range(n_nodes):
            if i == j:
                continue  # no self-loops
            edge_list.append([i, j])
            # Edge duration is the duration of the dst_host's observation
            dur = duration_list[j] if j < len(duration_list) else 0.0
            tcp_f = float(window_row.get("tcp_fraction", 1.0) or 1.0) if source_events is None else 1.0
            edge_features.append([dur, tcp_f])

    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.zeros((2, 0), dtype=torch.long)
    edge_attr = torch.tensor(edge_features, dtype=torch.float32) if edge_features else torch.zeros((0, 2), dtype=torch.float32)

    data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr)
    data.num_nodes = n_nodes
    return data


class GraphSAGEModel(nn.Module):
    """GraphSAGE (SAGE) model for episode-level incident classification."""

    def __init__(self, node_features: int = 4, hidden_dim: int = 16, num_classes: int = 2,
                 num_layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs = nn.ModuleList()
        self.convs.append(SAGEConv(node_features, hidden_dim))
        for _ in range(num_layers - 2):
            self.convs.append(SAGEConv(hidden_dim, hidden_dim))
        self.convs.append(SAGEConv(hidden_dim, hidden_dim))
        self.dropout = dropout
        self.readout = nn.Linear(hidden_dim, num_classes)

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index = data.x, data.edge_index

        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = F.relu(x)
            x = F.dropout(x, p=self.dropout, training=self.training)

        # Mean pooling over nodes for graph-level representation
        x = torch.mean(x, dim=0)
        x = self.readout(x)
        return x


class GATModel(nn.Module):
    """GAT (Graph Attention Network) model for episode-level incident classification."""

    def __init__(self, node_features: int = 4, hidden_dim: int = 16, num_classes: int = 2,
                 num_heads: int = 4, dropout: float = 0.5, concat_heads: bool = True):
        super().__init__()
        self.convs = nn.ModuleList()
        self.convs.append(GATConv(node_features, hidden_dim, heads=num_heads, dropout=dropout))
        for _ in range(2):
            self.convs.append(GATConv(hidden_dim * num_heads, hidden_dim, heads=num_heads,
                                      dropout=dropout, concat=concat_heads))
        self.readout = nn.Linear(hidden_dim * num_heads, num_classes)

    def forward(self, data: Data) -> torch.Tensor:
        x, edge_index = data.x, data.edge_index

        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=0.5, training=self.training)

        # Attention-based readout: mean pool node embeddings
        x = torch.mean(x, dim=0)
        x = self.readout(x)
        return x


def train_gnn_model(model: nn.Module, data_list: List[Data], labels: List[int],
                    epochs: int = 20, lr: float = 0.01, weight_decay: float = 1e-4,
                    device: str = "cuda" if torch.cuda.is_available() else "cpu") -> nn.Module:
    """Train a GNN model on a list of window graphs.

    Args:
        model: GNN model to train
        data_list: List of PyG Data objects (one per window)
        labels: Binary labels (0 = benign, 1 = incident)
        epochs: Number of training epochs
        lr: Learning rate
        weight_decay: L2 regularization
        device: Computation device

    Returns:
        Trained model
    """
    model.to(device)
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        model.train()
        for i, data in enumerate(data_list):
            data = data.to(device)
            optimizer.zero_grad()
            out = model(data)
            loss = criterion(out, torch.tensor(labels[i], dtype=torch.long, device=device))
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if epoch % 5 == 0 or epoch == epochs:
            print(f"  GNN Epoch {epoch}/{epochs}, loss={total_loss/len(data_list):.4f}")

    return model
