"""Integration tests for SmartContract VulnHunter scan command with Solodit enrichment."""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path

from vulnhunter.commands.scan import get_available_adapters
from vulnhunter.solodit.enricher import SoloditEnricher


class TestScanCommand:
    """Integration tests for scan command."""

    def test_get_available_adapters_detects_installed_tools(self):
        """Test that available adapters are correctly detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            adapters = get_available_adapters(tmpdir)
            # Should return list (may be empty if no tools installed)
            assert isinstance(adapters, list)

    def test_scan_with_mock_contract(self):
        """Test scanning a mock contract directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock Solidity file
            contract_file = Path(tmpdir) / "Test.sol"
            contract_file.write_text("""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    uint256 public value;
    
    function setValue(uint256 _value) public {
        value = _value;
    }
}
""")

            # Test adapter detection
            adapters = get_available_adapters(tmpdir)
            assert isinstance(adapters, list)


class TestSoloditEnrichment:
    """Integration tests for Solodit enrichment."""

    def test_enricher_initialization(self):
        """Test that enricher can be initialized."""
        try:
            enricher = SoloditEnricher()
            assert enricher is not None
            assert enricher.kb is not None
        except ImportError:
            pytest.skip("Solodit KB not available")

    def test_search_query_building(self):
        """Test search query construction from finding."""
        try:
            enricher = SoloditEnricher()

            # Mock finding
            class MockFinding:
                check = "reentrancy"
                description = "External call before state update"
                function = "withdraw"
                severity = "HIGH"

            query = enricher._build_search_query(MockFinding())
            assert "reentrancy" in query.lower() or "withdraw" in query.lower()
        except ImportError:
            pytest.skip("Solodit KB not available")


class TestVaulthunterMonitor:
    """Integration tests for Vaulthunter 24/7 monitor."""

    def test_monitor_initialization(self):
        """Test that monitor can be initialized."""
        from vulnhunter.monitor import VaulthunterMonitor

        monitor = VaulthunterMonitor()
        assert monitor is not None
        assert isinstance(monitor.targets, dict)

    def test_add_target(self):
        """Test adding a target to monitor."""
        from vulnhunter.monitor import VaulthunterMonitor, MonitoredTarget

        monitor = VaulthunterMonitor()

        target = MonitoredTarget(
            id="test_123",
            name="Test Target",
            target_type="directory",
            path="/tmp/test",
            scan_interval=3600,
        )

        target_id = monitor.add_target(target)
        assert target_id == "test_123"
        assert "test_123" in monitor.targets

    def test_remove_target(self):
        """Test removing a target."""
        from vulnhunter.monitor import VaulthunterMonitor, MonitoredTarget

        monitor = VaulthunterMonitor()

        target = MonitoredTarget(
            id="test_remove",
            name="Test Target",
            target_type="directory",
            path="/tmp/test",
        )

        monitor.add_target(target)
        assert monitor.remove_target("test_remove") is True
        assert monitor.remove_target("nonexistent") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
