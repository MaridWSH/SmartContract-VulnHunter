"""Tests for HeimdallAdapter."""

import asyncio
import json
from pathlib import Path
from typing import List

import pytest

from vulnhunter.adapters.heimdall_adapter import HeimdallAdapter
from vulnhunter.findings import Finding


class TestHeimdallAdapter:
    def test_is_available_returns_true_when_installed(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which", lambda x: "/usr/bin/heimdall" if x == "heimdall" else None
        )
        adapter = HeimdallAdapter()
        assert adapter.is_available() is True

    def test_is_available_returns_false_when_not_installed(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        adapter = HeimdallAdapter()
        assert adapter.is_available() is False

    @pytest.mark.asyncio
    async def test_run_parses_vulnerabilities_list(self, monkeypatch):
        stdout_data = {
            "vulnerabilities": [
                {
                    "name": "Reentrancy",
                    "description": "Potential reentrancy attack",
                    "severity": "High",
                    "location": "function withdraw()",
                }
            ]
        }
        mock_stdout = json.dumps(stdout_data)
        mock_stderr = ""
        mock_returncode = 0

        async def mock_run_decompile(target: str):
            return mock_stdout, mock_stderr, mock_returncode

        adapter = HeimdallAdapter()
        monkeypatch.setattr(adapter, "_run_decompile", mock_run_decompile)

        findings = await adapter.run("0x1234...")

        assert len(findings) == 1
        assert findings[0].title == "Heimdall: Reentrancy"
        assert findings[0].severity == "High"

    @pytest.mark.asyncio
    async def test_run_handles_non_zero_exit(self, monkeypatch):
        mock_stdout = ""
        mock_stderr = "Error: Invalid bytecode"
        mock_returncode = 1

        async def mock_run_decompile(target: str):
            return mock_stdout, mock_stderr, mock_returncode

        adapter = HeimdallAdapter()
        monkeypatch.setattr(adapter, "_run_decompile", mock_run_decompile)

        findings = await adapter.run("0x1234...")

        assert len(findings) == 1
        assert findings[0].severity == "High"
        assert "Invalid bytecode" in findings[0].description

    @pytest.mark.asyncio
    async def test_run_parses_abi_output(self, monkeypatch):
        stdout_data = {
            "abi": [
                {"name": "transfer", "type": "function"},
                {"name": "balanceOf", "type": "function"},
            ]
        }
        mock_stdout = json.dumps(stdout_data)

        async def mock_run_decompile(target: str):
            return mock_stdout, "", 0

        adapter = HeimdallAdapter()
        monkeypatch.setattr(adapter, "_run_decompile", mock_run_decompile)

        findings = await adapter.run("0x1234...")

        assert len(findings) == 2
        assert all(f.source == "heimdall" for f in findings)

    @pytest.mark.asyncio
    async def test_run_handles_invalid_json(self, monkeypatch):
        mock_stdout = "Not valid JSON"

        async def mock_run_decompile(target: str):
            return mock_stdout, "", 0

        adapter = HeimdallAdapter()
        monkeypatch.setattr(adapter, "_run_decompile", mock_run_decompile)

        findings = await adapter.run("0x1234...")

        assert len(findings) == 1
        assert findings[0].severity == "Info"


class TestHeimdallAdapterIntegration:
    """Integration tests that verify adapter behavior with real subprocess calls."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not HeimdallAdapter().is_available(),
        reason="heimdall not installed",
    )
    async def test_integration_with_real_heimdall(self):
        adapter = HeimdallAdapter()

        findings = await adapter.run("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")

        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)
