"""
Example usage of the platform-specific reporters.

This module demonstrates how to use each reporter with sample findings.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vulnhunter.reporters import (
    get_reporter,
    list_platforms,
    ImmunefiReporter,
    Code4renaReporter,
    SherlockReporter,
    CodehawksReporter,
)
from dataclasses import dataclass
from typing import Optional


@dataclass
class SampleFinding:
    """Example finding data structure."""

    id: int
    title: str
    description: str
    severity: str = "Medium"
    funds_at_risk: Optional[float] = None
    impact: Optional[int] = None
    likelihood: Optional[int] = None
    poc: Optional[str] = None


def demo_immunefi():
    """Demonstrate Immunefi reporter with funds-at-risk calculation."""
    print("=" * 60)
    print("IMMUNEFI REPORTER DEMO")
    print("=" * 60)

    reporter = ImmunefiReporter()

    findings = [
        SampleFinding(
            id=1,
            title="Reentrancy in withdraw function",
            description="The withdraw function is vulnerable to reentrancy attacks.",
            severity="High",
            funds_at_risk=500000.00,
            poc="""
// Attacker contract
contract Attacker {
    function attack() external {
        victim.withdraw();
    }
    
    receive() external payable {
        victim.withdraw();
    }
}
""",
        ),
        SampleFinding(
            id=2,
            title="Integer overflow in calculation",
            description="Unchecked arithmetic leads to overflow.",
            severity="Medium",
            funds_at_risk=5000.00,
        ),
    ]

    report = reporter.generate(findings, poc="See attached Foundry test file")
    print(report)
    print()


def demo_code4rena():
    """Demonstrate Code4rena reporter with High/Medium/Low categorization."""
    print("=" * 60)
    print("CODE4RENA REPORTER DEMO")
    print("=" * 60)

    reporter = Code4renaReporter()

    findings = [
        SampleFinding(
            id=1,
            title="Access control bypass",
            description="Unauthorized users can call admin functions.",
            severity="High",
            impact=4,
            likelihood=3,
            poc="Call adminFunction() from non-admin address",
        ),
        SampleFinding(
            id=2,
            title="Missing zero check",
            description="No validation for zero address.",
            severity="Low",
            impact=1,
            likelihood=2,
        ),
        SampleFinding(
            id=3,
            title="Timestamp manipulation",
            description="Block timestamp used for randomness.",
            severity="Medium",
            impact=3,
            likelihood=2,
        ),
    ]

    report = reporter.generate(findings)
    print(report)
    print()


def demo_sherlock():
    """Demonstrate Sherlock reporter with impact-based severity."""
    print("=" * 60)
    print("SHERLOCK REPORTER DEMO")
    print("=" * 60)

    reporter = SherlockReporter()

    findings = [
        SampleFinding(
            id=1,
            title="Flash loan attack vector",
            description="Price oracle can be manipulated via flash loans.",
            impact=5,
            likelihood=4,
            poc="Flash loan 10000 ETH, manipulate price, liquidate",
        ),
        SampleFinding(
            id=2,
            title="Event emission issue",
            description="Event not emitted on state change.",
            impact=1,
            likelihood=3,
        ),
    ]

    report = reporter.generate(findings)
    print(report)
    print()


def demo_codehawks():
    """Demonstrate Codehawks reporter with impact × likelihood matrix."""
    print("=" * 60)
    print("CODEHAWKS REPORTER DEMO")
    print("=" * 60)

    reporter = CodehawksReporter()

    findings = [
        SampleFinding(
            id=1,
            title="Critical: Fund drainage",
            description="Attacker can drain entire protocol.",
            impact=5,
            likelihood=5,
            poc="Repeated calls to drain() drain all funds",
        ),
        SampleFinding(
            id=2,
            title="High severity: Reward manipulation",
            description="Rewards can be inflated.",
            impact=4,
            likelihood=3,
        ),
        SampleFinding(
            id=3,
            title="Medium: Precision loss",
            description="Division before multiplication causes precision loss.",
            impact=3,
            likelihood=2,
        ),
    ]

    report = reporter.generate(findings)
    print(report)
    print()


def demo_factory():
    """Demonstrate using the factory function."""
    print("=" * 60)
    print("FACTORY FUNCTION DEMO")
    print("=" * 60)

    print("Supported platforms:", list_platforms())
    print()

    # Use factory to get reporter
    reporter = get_reporter("immunefi")
    print(f"Created reporter: {reporter.platform_name}")

    # Try invalid platform
    try:
        get_reporter("invalid_platform")
    except ValueError as e:
        print(f"Expected error: {e}")

    print()


if __name__ == "__main__":
    demo_immunefi()
    demo_code4rena()
    demo_sherlock()
    demo_codehawks()
    demo_factory()
