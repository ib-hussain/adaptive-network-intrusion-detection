import pytest
from src.code.early_warning import early_warning_metrics

MANIFEST = {
    "incident": dict(episode_id="incident", condition="incident", start_ts=10, milestone_ts=20, end_ts=25),
    "benign": dict(episode_id="benign", condition="benign", start_ts=1, milestone_ts=None, end_ts=9),
}


def test_lead_time_and_misses():
    predictions = [dict(episode_id="incident", window_end_ts=12, score=.1),
                   dict(episode_id="incident", window_end_ts=14, score=.85),
                   dict(episode_id="benign", window_end_ts=7, score=.1)]
    r = early_warning_metrics(predictions, MANIFEST, threshold=.5)
    assert r["pre_milestone_coverage"] == 1
    assert r["conditional_mean_lead_s"] == 6
    assert r["coverage_adjusted_mean_lead_s"] == 6
    assert r["false_positive_episode_rate"] == 0


def test_late_and_missing_not_called_early():
    r = early_warning_metrics([{"episode_id":"incident", "window_end_ts":23, "score":.9}], MANIFEST)
    assert r["pre_milestone_coverage"] == 0
    assert r["late_incidents"] == 1
    assert r["conditional_mean_lead_s"] is None


def test_reject_predictions_from_future():
    with pytest.raises(ValueError, match="outside"):
        early_warning_metrics([{"episode_id":"incident", "window_end_ts":26, "score":.9}], MANIFEST)


def test_bootstrap_ci_on_episode_units():
    from src.code.early_warning import early_warning_bootstrap_ci
    rows = [{"episode_id":"i1", "condition":"incident", "outcome":"early_warning", "lead_s":2.0},
            {"episode_id":"i2", "condition":"incident", "outcome":"missed", "lead_s":None},
            {"episode_id":"b1", "condition":"benign", "outcome":"no_alarm", "lead_s":None}]
    ci = early_warning_bootstrap_ci(rows, seed=1, repetitions=120)
    assert 0 <= ci["pre_milestone_coverage"][0] <= ci["pre_milestone_coverage"][1] <= 1
