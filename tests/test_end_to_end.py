"""End-to-end test for SmartContract VulnHunter framework."""

import asyncio
import tempfile
from pathlib import Path

from vulnhunter.core.orchestrator import Orchestrator
from vulnhunter.core.sarif_merger import SarifMerger
from vulnhunter.core.deduplicator import Deduplicator
from vulnhunter.adapters.mock_scanner_adapter import MockScannerAdapter


def test_end_to_end():
    """Test complete framework flow with mock scanner."""
    print("🧪 Testing SmartContract VulnHunter Framework...")

    # Create a mock project
    with tempfile.TemporaryDirectory() as tmpdir:
        project_dir = Path(tmpdir)

        # Create mock Solidity file
        (project_dir / "contracts").mkdir()
        (project_dir / "contracts" / "Example.sol").write_text(
            "pragma solidity ^0.8.0; contract Example {}"
        )

        # Create mock Rust file
        (project_dir / "src").mkdir()
        (project_dir / "src" / "lib.rs").write_text("fn main() {}")

        print(f"📁 Created mock project: {project_dir}")

        # Initialize components
        orchestrator = Orchestrator(max_concurrent=5)
        merger = SarifMerger()
        deduplicator = Deduplicator()

        # Create mock scanner task
        adapter = MockScannerAdapter()

        # Run scan
        print("🔍 Running mock scan...")
        findings = asyncio.run(adapter.run(str(project_dir)))

        print(f"✅ Found {len(findings)} issues:")
        for finding in findings:
            print(f"  - {finding.title} ({finding.severity})")

        # Test merging
        print("\n📊 Testing SARIF merger...")
        merged = merger.merge_findings([findings])
        print(f"✅ Merged {len(merged)} findings")

        # Test deduplication
        print("\n🔍 Testing deduplicator...")
        unique = deduplicator.deduplicate(merged)
        print(f"✅ {len(unique)} unique findings after dedup")

        # Test path normalization
        print("\n📁 Testing path normalization...")
        normalized = merger.normalize_paths(unique, project_dir)
        print(f"✅ Normalized {len(normalized)} paths")

        print("\n✅ All framework components working!")
        return True


if __name__ == "__main__":
    success = test_end_to_end()
    exit(0 if success else 1)
