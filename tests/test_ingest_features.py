import json
import pytest
from src.code.ingest import load_manifest, load_events
from src.code.features import make_windows, FEATURE_COLUMNS


def fixtures(tmp_path):
    man = tmp_path / "episodes.jsonl"
    events = tmp_path / "gateway.jsonl"
    episodes = [
        dict(episode_id="normal", condition="benign", policy="test", start_ts=1.0, end_ts=9.5, milestone_ts=None),
        dict(episode_id="controlled", condition="incident", policy="test", start_ts=10.0, end_ts=19.5, milestone_ts=18.0),
    ]
    with man.open("w") as f:
        for e in episodes: f.write(json.dumps(e) + "\n")
    with events.open("w") as f:
        for eid, start in (("normal", 1), ("controlled", 10)):
            for i in range(6):
                f.write(json.dumps(dict(ts=start + i, ts_end=start + i + .02, episode_id=eid,
                                        src_host="lab-a", dst_host="lab-b" if i % 2 else "lab-c",
                                        proto="tcp", orig_bytes=10, resp_bytes=20, duration=.02,
                                        sensor="application_gateway")) + "\n")
    return man, events


def test_ingest_and_causal_features(tmp_path):
    man, event_file = fixtures(tmp_path)
    manifest = load_manifest(man)
    events = load_events(event_file, manifest)
    rows = make_windows(events, manifest, n_events=4)
    assert len(rows) > 0
    assert all(set(FEATURE_COLUMNS).issubset(row) for row in rows)
    assert all(r["window_end_ts"] < 18 for r in rows if r["episode_id"] == "controlled")
    assert all("profile" not in r and "topology" not in r for r in rows)


def test_reject_duplicate_manifest(tmp_path):
    man, _ = fixtures(tmp_path)
    with man.open("a") as f: f.write(man.read_text().splitlines()[0] + "\n")
    with pytest.raises(ValueError, match="Duplicate"):
        load_manifest(man)


def test_reject_nan_event(tmp_path):
    man, file = fixtures(tmp_path)
    with file.open("a") as f:
        f.write(json.dumps({"ts": float('nan'), "episode_id": "normal", "sensor": "application_gateway"})+"\n")
    with pytest.raises(ValueError, match="Non-finite"):
        load_events(file, load_manifest(man))


def test_reject_ambiguous_zeek_episode(tmp_path):
    man, _ = fixtures(tmp_path)
    manifest = load_manifest(man)
    file = tmp_path / "zeek.jsonl"
    file.write_text(json.dumps({"ts": 11, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "orig_bytes": 5}) + "\n")
    e = load_events(file, manifest, source="zeek")
    assert e[0]["episode_id"] == "controlled"
