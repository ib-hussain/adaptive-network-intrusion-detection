"""Baselines and train-only model selection. No model evaluates held-out test labels during fit."""
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from .features import FEATURE_COLUMNS


def arrays(windows):
    x = np.array([[float(r[col]) for col in FEATURE_COLUMNS] for r in windows], dtype=np.float64)
    y = np.array([int(r["label"]) for r in windows], dtype=np.int64)
    if x.ndim != 2 or x.shape[1] != len(FEATURE_COLUMNS) or not np.isfinite(x).all():
        raise ValueError("Invalid model features")
    return x, y


def fit_baseline(windows, kind="rf", seed=0, n_estimators=150, max_depth=None, min_samples_leaf=2, max_features=1.0):
    x, y = arrays(windows)
    if len(x) < 6:
        raise ValueError("Too few training windows")
    if kind == "rf":
        if len(np.unique(y)) < 2:
            raise ValueError("Supervised training requires both benign and incident")
        model = RandomForestClassifier(n_estimators=n_estimators, class_weight="balanced_subsample", min_samples_leaf=min_samples_leaf,
                                       max_depth=max_depth, max_features=max_features,
                                       random_state=seed, n_jobs=-1)
        model.fit(x, y)
        return model
    if kind == "isolation_forest":
        benign = x[y == 0]
        if len(benign) < 4:
            raise ValueError("Insufficient benign training windows")
        model = make_pipeline(StandardScaler(), IsolationForest(n_estimators=100, random_state=seed, contamination="auto", n_jobs=-1))
        model.fit(benign)
        return model
    raise ValueError("Unknown model kind")


def predict_scores(model, windows, kind="rf"):
    if not windows:
        return []
    x, _ = arrays(windows)
    if kind == "rf":
        result = model.predict_proba(x)[:, list(model.classes_).index(1)]
    else:
        raw = model.decision_function(x)
        # Score is monotone relative to anomaly score; NOT calibrated probability.
        result = 1.0 / (1.0 + np.exp(np.clip(5 * raw, -50, 50)))
    return [{"episode_id": r["episode_id"], "window_end_ts": r["window_end_ts"], "score": float(p),
             "label": r["label"], "policy": r["policy"]} for r, p in zip(windows, result)]


def tune_forest(train, validation, seed=0, trials=10, db_path=None, study_name="baseline_rf"):
    """Resumable Optuna TPE over validation PR-AUC; needs a distinct group-held validation set."""
    if trials <= 0:
        return None
    import optuna
    xv, yv = arrays(validation)
    if len(np.unique(yv)) < 2:
        raise ValueError("Validation must contain both classes")
    xt, yt = arrays(train)
    if len(np.unique(yt)) < 2:
        raise ValueError("Training must contain both classes")
    def objective(trial):
        config = dict(n_estimators=trial.suggest_int("n_estimators", 60, 220, step=40),
                      max_depth=trial.suggest_int("max_depth", 3, 16),
                      min_samples_leaf=trial.suggest_int("min_samples_leaf", 1, 7),
                      max_features=trial.suggest_float("max_features", .5, 1.0))
        clf = RandomForestClassifier(class_weight="balanced_subsample", random_state=seed, n_jobs=-1, **config)
        clf.fit(xt, yt)
        scores = clf.predict_proba(xv)[:, list(clf.classes_).index(1)]
        metric = float(average_precision_score(yv, scores))
        if not np.isfinite(metric):
            raise ValueError("Non-finite trial metric")
        return metric
    storage = f"sqlite:///{db_path}" if db_path is not None else None
    study = optuna.create_study(direction="maximize", sampler=optuna.samplers.TPESampler(seed=seed),
                                storage=storage, study_name=study_name, load_if_exists=True)
    study.optimize(objective, n_trials=trials)
    return study.best_params
