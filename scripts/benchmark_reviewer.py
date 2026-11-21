"""Benchmark the local reviewer using fixed synthetic, already-masked text only."""

import argparse
import asyncio
import json
import math
import platform
import statistics
import subprocess
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from time import perf_counter

import httpx
from pydantic import SecretStr

from shield.detect.stage2 import OllamaReviewer, ReviewerUnavailable

TEXT = SecretStr(
    "Synthetic review sample. [PERSON_ABCD] works at [LOCATION_ABCD]. "
    "Contact [EMAIL_ABCD]. No additional identifying facts are supplied."
)


async def benchmark(model, samples, timeout):
    async with httpx.AsyncClient(
        base_url="http://127.0.0.1:11434",
        trust_env=False,
        follow_redirects=False,
        timeout=5,
    ) as client:
        tags = (await client.get("/api/tags")).json()
        info = next((item for item in tags["models"] if item["name"] == model), None)
        if info is None:
            raise ReviewerUnavailable()
        server = (await client.get("/api/version")).json()["version"]
    durations, valid = [], 0
    async with OllamaReviewer(model, timeout_s=timeout) as reviewer:
        for _ in range(samples + 1):
            start = perf_counter()
            output = await reviewer.review(TEXT)
            durations.append(round(perf_counter() - start, 6))
            try:
                parsed = json.loads(output.get_secret_value())
                valid += int(
                    isinstance(parsed, dict) and isinstance(parsed.get("spans"), list)
                )
            except ValueError:
                pass
    warm = durations[1:]

    def hardware(name):
        return subprocess.check_output(["sysctl", "-n", name], text=True).strip()

    return {
        "measured_at_utc": datetime.now(UTC).isoformat(),
        "model": model,
        "model_digest": info["digest"],
        "model_bytes": info["size"],
        "ollama_server": server,
        "architecture": platform.machine(),
        "os": platform.system(),
        "cpu": hardware("machdep.cpu.brand_string"),
        "memory_bytes": int(hardware("hw.memsize")),
        "python": platform.python_version(),
        "packages": {
            name: version(name)
            for name in ("langchain-ollama", "langchain-core", "ollama", "langsmith")
        },
        "timeout_s": timeout,
        "num_ctx": 4096,
        "num_predict": 256,
        "temperature": 0,
        "seed": 0,
        "synthetic_input_characters": len(TEXT.get_secret_value()),
        "first_call_s": durations[0],
        "warm_samples_s": warm,
        "warm_median_s": statistics.median(warm),
        "warm_p95_nearest_rank_s": sorted(warm)[math.ceil(0.95 * len(warm)) - 1],
        "json_spans_array_responses": valid,
        "total_calls": len(durations),
        "notes": (
            "Wall time includes availability checks and adapter overhead. "
            "No raw outputs retained."
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error("samples must be positive")
    try:
        result = asyncio.run(benchmark(args.model, args.samples, args.timeout))
    except ReviewerUnavailable, httpx.HTTPError, StopIteration:
        parser.exit(1, "Local reviewer benchmark failed. No response text retained.\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
