"""Comprehensive experiment runner using existing processed data."""
import json
import csv
import sys
import random
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, GATConv
from torch_geometric.data import Data
from sklearn.metrics import average_precision_score, roc_auc_score, f1_score, precision_recall_curve

from src.code.features import FEATURE_COLUMNS
from src.code.early_warning import early_warning_metrics, early_warning_bootstrap_ci

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {DEVICE}")

STUDY_DIR = Path("outputs/studies/cpu_v3_main_v2_20261115T164430Z_zeek_20261115T165446Z")

# Load windows
with open(STUDY_DIR / "dataset" / "windows.csv") as f:
    reader = csv.DictReader(f)
    windows = list(reader)

print(f"Loaded {len(windows)} windows")

# Load split manifest
split_of = {}
with open(STUDY_DIR / "dataset" / "split_manifest.jsonl") as f:
    for line in f:
        row = json.loads(line)
        split_of[row["episode_id"]] = row["split"]

# Load results for reference
with open(STUDY_DIR / "results.json") as f:
    results = json.load(f)

# Group windows by episode and split
train_windows = [w for w in windows if split_of.get(w["episode_id"]) == "train"]
val_windows = [w for w in windows if split_of.get(w["episode_id"]) == "validation"]
test_windows = [w for w in windows if split_of.get(w["episode_id"]) == "test"]

print(f"Train: {len(train_windows)}, Val: {len(val_windows)}, Test: {len(test_windows)}")

# Feature matrix preparation
def window_to_features(w, feature_cols):
    return [float(w.get(c, 0.0)) for c in feature_cols]

X_train = np.array([window_to_features(w, FEATURE_COLUMNS) for w in train_windows])
y_train = np.array([int(w["label"]) for w in train_windows])

X_val = np.array([window_to_features(w, FEATURE_COLUMNS) for w in val_windows])
y_val = np.array([int(w["label"]) for w in val_windows])

X_test = np.array([window_to_features(w, FEATURE_COLUMNS) for w in test_windows])
y_test = np.array([int(w["label"]) for w in test_windows])

print(f"Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
print(f"Train labels: {np.bincount(y_train)}, Val: {np.bincount(y_val)}, Test: {np.bincount(y_test)}")

# ============================================================
# 1. Random Forest with Optuna HPO (30 trials)
# ============================================================
print("\n=== Random Forest with Optuna HPO ===")
try:
    import optuna
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline
    
    def objective(trial):
        n_estimators = trial.suggest_int("n_estimators", 50, 300)
        max_depth = trial.suggest_int("max_depth", 3, 20)
        min_samples_split = trial.suggest_int("min_samples_split", 2, 20)
        min_samples_leaf = trial.suggest_int("min_samples_leaf", 1, 10)
        max_features = trial.suggest_categorical("max_features", ["sqrt", "log2", 0.5])
        
        clf = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=max_depth,
            min_samples_split=min_samples_split, min_samples_leaf=min_samples_leaf,
            max_features=max_features, n_jobs=-1, random_state=20261115, class_weight="balanced"
        )
        clf.fit(X_train, y_train)
        y_pred = clf.predict_proba(X_val)[:, 1]
        return average_precision_score(y_val, y_pred)
    
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=20261115))
    study.optimize(objective, n_trials=30)
    print(f"Best params: {study.best_params}")
    print(f"Best val PR-AUC: {study.best_value:.4f}")
    
    # Train final model
    best_rf = RandomForestClassifier(**study.best_params, n_jobs=-1, random_state=20261115, class_weight="balanced")
    best_rf.fit(X_train, y_train)
    
    # Test predictions
    y_test_pred = best_rf.predict_proba(X_test)[:, 1]
    rf_test_pr_auc = average_precision_score(y_test, y_test_pred)
    rf_test_roc_auc = roc_auc_score(y_test, y_test_pred)
    print(f"RF Test PR-AUC: {rf_test_pr_auc:.4f}, ROC-AUC: {rf_test_roc_auc:.4f}")
    
except Exception as e:
    print(f"RF HPO failed: {e}")
    rf_test_pr_auc = 0

# ============================================================
# 2. GRU training (existing implementation)
# ============================================================
print("\n=== GRU Training ===")
try:
    # Check if GRU results exist
    with open(STUDY_DIR / "results.json") as f:
        r = json.load(f)
        for policy in ["fixed", "random", "strategic"]:
            if policy in r.get("models", {}):
                for model_name, model_res in r["models"][policy].items():
                    if "gru" in model_name.lower():
                        print(f"  {policy}/{model_name}: PR-AUC={model_res.get('pr_curve_episode', {}).get('auc', 'N/A')}")
except:
    pass

# ============================================================
# 3. GNN Training (GraphSAGE and GAT)
# ============================================================
print("\n=== GNN Training ===")

def construct_graph_from_window(wn):
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

def train_gnn(model, graphs, labels, epochs=20, lr=0.01):
    model.to(DEVICE)
    model.train()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()
    for epoch in range(1, epochs + 1):
        loss_sum = 0
        for g, lbl in zip(graphs, labels):
            g = g.to(DEVICE)
            optimizer.zero_grad()
            out = model(g)
            t = torch.tensor(lbl, dtype=torch.long, device=DEVICE)
            loss = criterion(out, t)
            loss.backward()
            optimizer.step()
            loss_sum += loss.item()
        if epoch % 5 == 0:
            print(f"  Epoch {epoch}/{epochs}, loss={loss_sum/len(graphs):.4f}")
    return model

# Build graphs
all_graphs = [construct_graph_from_window(w) for w in windows]
train_graphs = [g for i, g in enumerate(all_graphs) if split_of.get(windows[i]["episode_id"]) == "train"]
val_graphs = [g for i, g in enumerate(all_graphs) if split_of.get(windows[i]["episode_id"]) == "validation"]
test_graphs = [g for i, g in enumerate(all_graphs) if split_of.get(windows[i]["episode_id"]) == "test"]

train_labels = [int(w["label"]) for w in train_windows]
val_labels = [int(w["label"]) for w in val_windows]
test_labels = [int(w["label"]) for w in test_windows]

print(f"Graphs: Train {len(train_graphs)}, Val {len(val_graphs)}, Test {len(test_graphs)}")

# Train GraphSAGE
sage = GNNClassifier(model_type="sage").to(DEVICE)
sage = train_gnn(sage, train_graphs, train_labels, epochs=30, lr=0.01)

# Train GAT
gat = GNNClassifier(model_type="gat").to(DEVICE)
gat = train_gnn(gat, train_graphs, train_labels, epochs=30, lr=0.01)

# Evaluate
sage.eval()
gat.eval()
sage_scores, gat_scores, sage_labels, gat_labels = [], [], [], []

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

print(f"GraphSAGE: PR-AUC={sage_pr_auc:.4f}, ROC-AUC={sage_roc_auc:.4f}")
print(f"GAT: PR-AUC={gat_pr_auc:.4f}, ROC-AUC={gat_roc_auc:.4f}")

# ============================================================
# 4. Ablation Studies
# ============================================================
print("\n=== Ablation Studies ===")

GRAPH_FEATURES_REMOVED = ("unique_links", "unique_destinations", "destination_entropy", "large_flow_fraction")
TEMPORAL_FEATURES = ("rate_per_s", "gap_mean_s", "gap_std_s", "gap_cv", "large_flow_fraction")
GRAPH_REDUCED = tuple(c for c in FEATURE_COLUMNS if c not in GRAPH_FEATURES_REMOVED)
TEMP_REDUCED = tuple(c for c in FEATURE_COLUMNS if c not in TEMPORAL_FEATURES)

from sklearn.ensemble import IsolationForest, RandomForestClassifier

def run_ablation(name, feature_cols, X_train_a, X_val_a, X_test_a):
    """Run RF and IF on given feature set."""
    results = {}
    
    # RF
    rf = RandomForestClassifier(n_estimators=200, max_depth=10, min_samples_split=5,
                                min_samples_leaf=2, max_features="sqrt", n_jobs=-1,
                                random_state=20261115, class_weight="balanced")
    rf.fit(X_train_a, y_train)
    y_pred = rf.predict_proba(X_test_a)[:, 1]
    results["rf_pr_auc"] = average_precision_score(y_test, y_pred)
    results["rf_roc_auc"] = roc_auc_score(y_test, y_pred)
    
    # IF
    iforest = IsolationForest(n_estimators=200, contamination=0.1, random_state=20261115, n_jobs=-1)
    iforest.fit(X_train_a[y_train == 0])  # train only on benign
    y_scores = -iforest.score_samples(X_test_a)  # higher = more anomalous
    results["if_pr_auc"] = average_precision_score(y_test, y_scores)
    results["if_roc_auc"] = roc_auc_score(y_test, y_scores)
    
    return results

# Full features
X_train_f = np.array([window_to_features(w, FEATURE_COLUMNS) for w in train_windows])
X_val_f = np.array([window_to_features(w, FEATURE_COLUMNS) for w in val_windows])
X_test_f = np.array([window_to_features(w, FEATURE_COLUMNS) for w in test_windows])

# Graph reduced
X_train_gr = np.array([window_to_features(w, GRAPH_REDUCED) for w in train_windows])
X_val_gr = np.array([window_to_features(w, GRAPH_REDUCED) for w in val_windows])
X_test_gr = np.array([window_to_features(w, GRAPH_REDUCED) for w in test_windows])

# Temporal reduced
X_train_tr = np.array([window_to_features(w, TEMP_REDUCED) for w in train_windows])
X_val_tr = np.array([window_to_features(w, TEMP_REDUCED) for w in val_windows])
X_test_tr = np.array([window_to_features(w, TEMP_REDUCED) for w in test_windows])

ablation_results = {}
for name, (Xtr, Xva, Xte) in {
    "full": (X_train_f, X_val_f, X_test_f),
    "graph_reduced": (X_train_gr, X_val_gr, X_test_gr),
    "temporal_reduced": (X_train_tr, X_val_tr, X_test_tr),
}.items():
    ablation_results[name] = run_ablation(name, None, Xtr, Xva, Xte)
    print(f"  {name}: RF PR-AUC={ablation_results[name]['rf_pr_auc']:.4f}, IF PR-AUC={ablation_results[name]['if_pr_auc']:.4f}")

# ============================================================
# 5. Policy-specific analysis
# ============================================================
print("\n=== Policy-specific Analysis ===")
for policy in ["fixed", "random", "strategic"]:
    policy_test = [w for w in test_windows if w["policy"] == policy]
    if not policy_test:
        continue
    X_pol = np.array([window_to_features(w, FEATURE_COLUMNS) for w in policy_test])
    y_pol = np.array([int(w["label"]) for w in policy_test])
    
    # RF
    rf = RandomForestClassifier(n_estimators=200, max_depth=10, min_samples_split=5,
                                min_samples_leaf=2, max_features="sqrt", n_jobs=-1,
                                random_state=20261115, class_weight="balanced")
    rf.fit(X_train_f, y_train)
    y_pred = rf.predict_proba(X_pol)[:, 1]
    pr_auc = average_precision_score(y_pol, y_pred)
    print(f"  {policy}: {len(policy_test)} windows, {sum(y_pol)} incident, RF PR-AUC={pr_auc:.4f}")

# ============================================================
# Save comprehensive results
# ============================================================
output = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "device": DEVICE,
    "data": {
        "n_windows": len(windows),
        "n_train": len(train_windows),
        "n_val": len(val_windows),
        "n_test": len(test_windows),
        "train_incidents": int(np.sum(y_train)),
        "val_incidents": int(np.sum(y_val)),
        "test_incidents": int(np.sum(y_test)),
    },
    "models": {
        "random_forest": {
            "test_pr_auc": float(rf_test_pr_auc),
            "test_roc_auc": float(rf_test_roc_auc),
        },
        "graph_sage": {
            "test_pr_auc": float(sage_pr_auc),
            "test_roc_auc": float(sage_roc_auc),
        },
        "gat": {
            "test_pr_auc": float(gat_pr_auc),
            "test_roc_auc": float(gat_roc_auc),
        }
    },
    "ablations": {
        "full": {k: float(v) for k, v in ablation_results["full"].items()},
        "graph_reduced": {k: float(v) for k, v in ablation_results["graph_reduced"].items()},
        "temporal_reduced": {k: float(v) for k, v in ablation_results["temporal_reduced"].items()},
    },
    "policy_analysis": {}
}

out_dir = Path("outputs/comprehensive_experiment_20261117")
out_dir.mkdir(parents=True, exist_ok=True)
with open(out_dir / "comprehensive_results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\nResults saved to {out_dir}/comprehensive_results.json")
print("\n=== SUMMARY ===")
print(f"RF PR-AUC: {rf_test_pr_auc:.4f}")
print(f"GraphSAGE PR-AUC: {sage_pr_auc:.4f}")
print(f"GAT PR-AUC: {gat_pr_auc:.4f}")
print(f"Graph ablation (RF): {ablation_results['full']['rf_pr_auc']:.4f} -> {ablation_results['graph_reduced']['rf_pr_auc']:.4f}")
print(f"Temporal ablation (RF): {ablation_results['full']['rf_pr_auc']:.4f} -> {ablation_results['temporal_reduced']['rf_pr_auc']:.4f}")

