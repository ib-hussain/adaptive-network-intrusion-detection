import pytest
from src.code.pipeline import split_episode_ids


def test_disjoint_splits():
    m = {}
    for j in range(8):
        for cond in ["benign", "incident"]:
            eid = f"{j}-{cond}"
            m[eid] = dict(episode_id=eid, condition=cond, policy="fixed")
    a, b = split_episode_ids(m,"fixed",2026)
    assert not a.intersection(b)
    assert len(a | b) == len(m)
    assert len({m[i]["condition"] for i in b}) == 2


def test_insufficient_split_refused():
    m = {str(j):dict(episode_id=str(j),condition="incident",policy="fixed") for j in range(2)}
    with pytest.raises(ValueError):
        split_episode_ids(m,"fixed")
