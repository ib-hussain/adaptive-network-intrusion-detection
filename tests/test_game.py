import math
import pytest
from src.code.game import Exp3, payoff


def test_exp3_distribution_and_update():
    agent = Exp3(["a", "b", "c"], seed=11)
    assert math.isclose(sum(agent.probabilities()), 1.0)
    for _ in range(50):
        assert agent.choose() in agent.actions
        agent.observe(.8)
        assert math.isclose(sum(agent.probabilities()), 1.0)
        assert all(x > 0 for x in agent.probabilities())


def test_no_reward_before_choice():
    with pytest.raises(ValueError):
        Exp3([1, 2]).observe(.1)


def test_reference_payoff_in_bounds():
    outcome = payoff("fanout", "spread", [.05] * 10, ["a", "b"] * 6)
    assert outcome.detected_by_reference
    assert 0 <= outcome.attacker_reward <= 1
    assert 0 <= outcome.defender_reward <= 1
