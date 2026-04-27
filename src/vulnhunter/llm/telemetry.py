"""Cost and telemetry tracking for LLM calls."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class CallRecord:
    timestamp: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float


class CostTracker:
    """Thread-safe tracker for LLM API costs and token usage."""

    def __init__(self):
        self._lock = threading.Lock()
        self._records: List[CallRecord] = []

    def add_call(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> None:
        with self._lock:
            self._records.append(
                CallRecord(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    model=model,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    cost_usd=cost_usd,
                )
            )

    def summary(self) -> Dict[str, any]:
        with self._lock:
            per_model: Dict[str, Dict[str, float]] = {}
            total_cost = 0.0
            total_input = 0
            total_output = 0

            for r in self._records:
                total_cost += r.cost_usd
                total_input += r.input_tokens
                total_output += r.output_tokens

                if r.model not in per_model:
                    per_model[r.model] = {
                        "calls": 0,
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cost_usd": 0.0,
                    }
                per_model[r.model]["calls"] += 1
                per_model[r.model]["input_tokens"] += r.input_tokens
                per_model[r.model]["output_tokens"] += r.output_tokens
                per_model[r.model]["cost_usd"] += r.cost_usd

            return {
                "total_calls": len(self._records),
                "total_cost_usd": round(total_cost, 6),
                "total_input_tokens": total_input,
                "total_output_tokens": total_output,
                "per_model": per_model,
            }

    def write_report(self, output_path: Path) -> None:
        report = self.summary()
        report["records"] = [
            {
                "timestamp": r.timestamp,
                "model": r.model,
                "input_tokens": r.input_tokens,
                "output_tokens": r.output_tokens,
                "cost_usd": round(r.cost_usd, 8),
            }
            for r in self._records
        ]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2))

    def reset(self) -> None:
        with self._lock:
            self._records.clear()
