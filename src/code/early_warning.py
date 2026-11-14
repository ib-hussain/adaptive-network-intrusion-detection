"""Incident-centred early warning: no future lookahead, misses are not excluded."""
from collections import defaultdict
import math
import statistics


def early_warning_metrics(predictions, manifest, threshold=0.5, persistence=1):
    if not 0 <= threshold <= 1 or persistence < 1:
        raise ValueError("Invalid threshold/persistence")
    grouped = defaultdict(list)
    for row in predictions:
        eid = row["episode_id"]
        if eid not in manifest:
            raise ValueError("Prediction belongs to an unknown episode")
        score, end = float(row["score"]), float(row["window_end_ts"])
        if not math.isfinite(score) or not 0 <= score <= 1 or not math.isfinite(end):
            raise ValueError("Non-finite score or time")
        grouped[eid].append(row)
    details = []
    leads = []
    false_episodes = 0
    benign_count = 0
    benign_seconds = 0.0
    incident_count = 0
    detected_incidents = 0
    late_incidents = 0
    pre_onset_warning_episodes = 0
    for eid, ep in manifest.items():
        rows = sorted(grouped.get(eid, []), key=lambda r: r["window_end_ts"])
        start, end = float(ep["start_ts"]), float(ep["end_ts"])
        onset = float(ep.get("onset_ts") or start) if ep["condition"] == "incident" else start
        if not start <= onset <= end:
            raise ValueError("Invalid onset timestamp")
        first_valid_alert = None
        pre_onset_alarm = False
        streak = 0
        # We require non-decreasing observation time and do not count a post-milestone alert as early.
        for r in rows:
            timestamp = float(r["window_end_ts"])
            if not start - 1e-6 <= timestamp <= end + 1e-6:
                raise ValueError("Prediction uses data outside its episode")
            # Pre-onset alarms on an incident are NOT valid early warnings.
            # Do not let a streak begun before onset meet persistence afterwards.
            if ep["condition"] == "incident" and timestamp < onset:
                pre_onset_alarm = pre_onset_alarm or float(r["score"]) >= threshold
                streak = 0
                continue
            streak = streak + 1 if float(r["score"]) >= threshold else 0
            if streak >= persistence:
                first_valid_alert = timestamp
                break
        if ep["condition"] == "benign":
            benign_count += 1
            benign_seconds += max(0.0, end - start)
            false_episodes += int(first_valid_alert is not None)
            details.append({"episode_id": eid, "condition": "benign", "outcome": "false_alarm" if first_valid_alert is not None else "no_alarm", "lead_s": None})
        else:
            incident_count += 1
            pre_onset_warning_episodes += int(pre_onset_alarm)
            impact = float(ep["milestone_ts"])
            if not onset < impact <= end:
                raise ValueError("Invalid incident milestone ordering")
            if first_valid_alert is not None and first_valid_alert < impact:
                detected_incidents += 1
                lead = impact - first_valid_alert
                leads.append(lead)
                outcome = "early_warning"
            elif first_valid_alert is not None:
                late_incidents += 1
                lead = None
                outcome = "late_detection"
            else:
                lead = None
                outcome = "missed"
            details.append({"episode_id": eid, "condition": "incident", "outcome": outcome, "lead_s": lead})
    return {
        "n_incidents": incident_count, "n_benign": benign_count,
        "pre_milestone_coverage": detected_incidents / incident_count if incident_count else None,
        "conditional_mean_lead_s": statistics.mean(leads) if leads else None,
        "conditional_median_lead_s": statistics.median(leads) if leads else None,
        "coverage_adjusted_mean_lead_s": sum(leads) / incident_count if incident_count else None,
        "false_positive_episode_rate": false_episodes / benign_count if benign_count else None,
        "false_alarms_per_benign_hour": false_episodes / (benign_seconds / 3600) if benign_seconds > 0 else None,
        "pre_onset_warning_episodes": pre_onset_warning_episodes, "pre_onset_warning_rate": pre_onset_warning_episodes / incident_count if incident_count else None,
        "late_incidents": late_incidents, "missed_incidents": incident_count - detected_incidents - late_incidents,
        "episode_results": details,
    }


def early_warning_bootstrap_ci(episode_results, seed=20261112, repetitions=500):
    """Stratified episode-level bootstrap, not repeated overlapping-window resampling."""
    import random
    incident = [r for r in episode_results if r["condition"] == "incident"]
    benign = [r for r in episode_results if r["condition"] == "benign"]
    if not incident or not benign or repetitions < 100:
        return None
    rng = random.Random(seed)
    coverage, adjusted, fpr = [], [], []
    for _ in range(repetitions):
        sampled_i = rng.choices(incident, k=len(incident))
        sampled_b = rng.choices(benign, k=len(benign))
        leads = [float(r["lead_s"]) if r["outcome"] == "early_warning" else 0.0 for r in sampled_i]
        coverage.append(sum(r["outcome"] == "early_warning" for r in sampled_i) / len(sampled_i))
        adjusted.append(sum(leads) / len(leads))
        fpr.append(sum(r["outcome"] == "false_alarm" for r in sampled_b) / len(sampled_b))
    def bounds(nums):
        vals = sorted(nums)
        return [vals[int(.025 * (len(vals)-1))], vals[int(.975 * (len(vals)-1))]]
    return {"pre_milestone_coverage": bounds(coverage),
            "coverage_adjusted_mean_lead_s": bounds(adjusted),
            "false_positive_episode_rate": bounds(fpr),
            "unit": "episode", "bootstrap_repetitions": repetitions}
