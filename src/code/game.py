"""Transparent bounded two-player repeated game (EXP3 bandit policy)."""
from dataclasses import dataclass
import math
import random

PROFILES = ("paced", "bursty", "fanout")
DEFENCES = ("rate", "spread")


class Exp3:
    """Bandit-policy update; no use of future/test outcomes."""
    def __init__(self, actions, seed=0, gamma=0.15):
        if not actions or not 0 < gamma <= 1:
            raise ValueError("Invalid actions/gamma")
        self.actions = tuple(actions)
        self.gamma = gamma
        self.weights = [1.0] * len(actions)
        self.random = random.Random(seed)
        self.previous = None

    def probabilities(self):
        total = sum(self.weights)
        k = len(self.weights)
        return [(1 - self.gamma) * w / total + self.gamma / k for w in self.weights]

    def choose(self):
        probs = self.probabilities()
        position = self.random.choices(range(len(probs)), weights=probs, k=1)[0]
        self.previous = (position, probs[position])
        return self.actions[position]

    def observe(self, reward):
        if self.previous is None or not 0 <= reward <= 1:
            raise ValueError("Choose first and reward must be in [0,1]")
        position, prob = self.previous
        exponent = min(20.0, self.gamma * reward / (prob * len(self.weights)))
        self.weights[position] *= math.exp(exponent)
        scale = max(self.weights)
        self.weights = [x / scale for x in self.weights]
        self.previous = None


@dataclass
class GameOutcome:
    profile: str
    defence: str
    detected_by_reference: bool
    attacker_reward: float
    defender_reward: float


def reference_alert(profile: str, defence: str, timing_gaps: list[float], destinations: list[str]):
    """Transparent heuristic reference *for scenario selection only*, not the trained IDS."""
    if defence not in DEFENCES or profile not in PROFILES:
        raise ValueError("Unknown bounded game action")
    if defence == "rate":
        # A short interarrival gap indicates burst traffic; independent of labels.
        return bool(timing_gaps) and min(timing_gaps) < 0.02
    return len(set(destinations)) >= 2 and len(destinations) >= 6


def payoff(profile: str, defence: str, gaps: list[float], destinations: list[str]) -> GameOutcome:
    detected = reference_alert(profile, defence, gaps, destinations)
    # Action cost penalises excessive bursty test traffic; bounded safe example.
    cost = {"paced": 0.05, "bursty": 0.2, "fanout": 0.1}[profile]
    attacker = max(0.0, min(1.0, (0.9 if not detected else 0.05) - cost))
    defender = 0.9 if detected else 0.05
    return GameOutcome(profile, defence, detected, attacker, defender)
