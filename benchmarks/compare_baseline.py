"""Compare benchmark results against baseline and fail on regression."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Any


def load_results(path: Path) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)


def compare_metrics(current: Dict, baseline: Dict, thresholds: Dict) -> list[str]:
    """Compare current vs baseline metrics. Returns list of failure messages."""
    failures = []

    # VDR (Vulnerability Detection Rate) - higher is better
    current_vdr = current.get("vdr", 0)
    baseline_vdr = baseline.get("vdr", 0)
    vdr_threshold = thresholds.get("vdr_regression_pp", 3.0)
    if baseline_vdr - current_vdr > vdr_threshold:
        failures.append(
            f"VDR regression: {current_vdr:.2f}% vs baseline {baseline_vdr:.2f}% "
            f"(threshold: {vdr_threshold}pp)"
        )

    # OI (Overreporting Index) - lower is better
    current_oi = current.get("oi", 0)
    baseline_oi = baseline.get("oi", 0)
    oi_threshold = thresholds.get("oi_regression", 0.01)
    if current_oi - baseline_oi > oi_threshold:
        failures.append(
            f"OI regression: {current_oi:.4f} vs baseline {baseline_oi:.4f} "
            f"(threshold: {oi_threshold})"
        )

    # Per-class detection rates
    current_classes = current.get("per_class", {})
    baseline_classes = baseline.get("per_class", {})
    class_threshold = thresholds.get("class_regression_pp", 10.0)

    for class_name, baseline_rate in baseline_classes.items():
        current_rate = current_classes.get(class_name, 0)
        if baseline_rate - current_rate > class_threshold:
            failures.append(
                f"Class '{class_name}' detection regression: "
                f"{current_rate:.2f}% vs baseline {baseline_rate:.2f}% "
                f"(threshold: {class_threshold}pp)"
            )

    return failures


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: compare_baseline.py <current.json> <baseline.json> [--thresholds thresholds.json]")
        return 1

    current_path = Path(sys.argv[1])
    baseline_path = Path(sys.argv[2])

    current = load_results(current_path)
    baseline = load_results(baseline_path)

    # Load thresholds
    thresholds = {
        "vdr_regression_pp": 3.0,
        "oi_regression": 0.01,
        "class_regression_pp": 10.0,
    }

    if "--thresholds" in sys.argv:
        idx = sys.argv.index("--thresholds")
        if idx + 1 < len(sys.argv):
            with open(sys.argv[idx + 1]) as f:
                thresholds.update(json.load(f))

    failures = compare_metrics(current, baseline, thresholds)

    if failures:
        print("BENCHMARK REGRESSION DETECTED:")
        for failure in failures:
            print(f"  ❌ {failure}")
        return 1
    else:
        print("✅ All benchmarks within acceptable thresholds")
        return 0


if __name__ == "__main__":
    sys.exit(main())
