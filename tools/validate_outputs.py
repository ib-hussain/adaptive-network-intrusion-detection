"""Standalone reproducibility checks for generated Phase 3 result directories."""
import argparse
import json
import math
from pathlib import Path


def validate(folder):
    p = Path(folder)
    results = json.loads((p / "results.json").read_text(encoding="utf-8"))
    splits = json.loads((p / "splits.json").read_text(encoding="utf-8"))
    holdout = set(splits["test"]["held_out"])
    if not holdout:
        raise ValueError("Missing independent held-out episodes")
    for policy in ("fixed", "random", "strategic"):
        tr = set(splits[policy]["train"])
        va = set(splits[policy]["validation"])
        if not tr or not va or (tr & va) or (tr & holdout) or (va & holdout):
            raise ValueError(f"Invalid episode splits for {policy}")
        for method in results["methods"][policy]["models"].values():
            if method["status"] != "evaluated":
                continue
            threshold = method["threshold_chosen_on_validation"]
            if not 0 <= threshold <= 1:
                raise ValueError("Threshold invalid")
            for group in (method["detection_all_windows_including_milestone"], method["detection_pre_milestone"], method["warning"]):
                for key, value in group.items():
                    if isinstance(value, (int, float)) and not math.isfinite(value):
                        raise ValueError(f"Non-finite metric {key}")
            if method["warning"]["pre_milestone_coverage"] is None:
                raise ValueError("Early warning requires labelled incidents")
    return {"status": "validated_structure_and_finiteness", "policies": 3,
            "held_out_episodes": len(holdout), "experimental_validity": "not_established_by_this_checker"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-directory", required=True)
    a = parser.parse_args()
    print(json.dumps(validate(a.results_directory), indent=2))

if __name__ == "__main__":
    main()
