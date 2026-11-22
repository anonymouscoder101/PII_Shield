"""Generate local labeled synthetic PII cases, without printing their contents."""

import argparse
import json
from pathlib import Path

from eval.synthetic import generate_dataset


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--count", type=int, default=150)
    parser.add_argument(
        "--output", type=Path, default=Path("eval/datasets/generated/synthetic.json")
    )
    args = parser.parse_args()
    if args.count < 1:
        parser.error("count must be positive")
    manifest = generate_dataset(seed=args.seed, count=args.count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"Generated {args.count} synthetic cases (seed={args.seed}).")


if __name__ == "__main__":
    main()
