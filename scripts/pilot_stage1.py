"""Run the offline Stage 1 pilot and export aggregate results only."""

import argparse
import asyncio
import json
from pathlib import Path

from eval.pilot import run_pilot
from eval.synthetic import generate_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--count", type=int, default=36)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--thresholds", nargs="+", type=float, default=[0.3, 0.5, 0.6])
    parser.add_argument("--allowlist-first-email", action="store_true")
    parser.add_argument(
        "--output", type=Path, default=Path("eval/results/stage1-pilot.json")
    )
    args = parser.parse_args()
    if args.count < 1:
        parser.error("count must be positive")
    if any(not 0 <= value <= 1 for value in args.thresholds):
        parser.error("thresholds must be between zero and one")
    dataset = (
        json.loads(args.dataset.read_text())
        if args.dataset
        else generate_dataset(seed=args.seed, count=args.count)
    )
    allowlist = []
    if args.allowlist_first_email:
        email = next(
            (
                entity["value"]
                for case in dataset["cases"]
                for entity in case["entities"]
                if entity["entity_type"] == "EMAIL_ADDRESS"
            ),
            None,
        )
        if email is None:
            parser.error("dataset has no email to allowlist")
        allowlist.append(email)
    result = asyncio.run(
        run_pilot(dataset, thresholds=args.thresholds, allowlist=allowlist)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    for row in result["thresholds"]:
        disclosure = row["disclosure"]
        print(
            f"threshold={row['threshold']}: "
            f"residual={disclosure['residual_non_allowlisted_occurrences']}/"
            f"{disclosure['labeled_occurrences']}; "
            f"allowlisted={disclosure['intentional_allowlisted_occurrences']}; "
            f"copy_proxy={row['utility_proxy']['whole_answer_exact_rate']:.3f}"
        )


if __name__ == "__main__":
    main()
