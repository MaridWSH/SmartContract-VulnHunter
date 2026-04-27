"""Auto-generate Halmos property tests from invariant candidates."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from vulnhunter.recon.models.recon_report import ReconReport

logger = logging.getLogger(__name__)


class PropertyGenerator:
    """Generate check_* property tests for Halmos from recon invariants."""

    def generate(self, recon: ReconReport, output_dir: Path) -> List[Path]:
        """Generate property tests and write to test/properties/.

        Returns list of written file paths.
        """
        candidates = getattr(recon, "invariant_candidates", []) or []
        if not candidates:
            logger.info("No invariant candidates in recon report; skipping property generation")
            return []

        out = output_dir / "test" / "properties"
        out.mkdir(parents=True, exist_ok=True)

        written: List[Path] = []
        for idx, inv in enumerate(candidates, 1):
            code = self._render(inv, idx)
            fp = out / f"property_{idx}.t.sol"
            fp.write_text(code)
            written.append(fp)

        return written

    def _render(self, invariant: str, idx: int) -> str:
        """Render a single property test from an invariant description."""
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

contract PropertyTest{idx} is Test {{
    // Invariant: {invariant}

    function check_invariant() public pure {{
        // TODO: replace with actual protocol state and assertion
        // This is a scaffold generated from recon invariant candidate.
        assert(true);
    }}
}}
"""
