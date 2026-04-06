"""Tests for CargoAuditAdapter."""

import json
from typing import List

import pytest

from vulnhunter.adapters.cargo_audit_adapter import CargoAuditAdapter
from vulnhunter.findings import Finding


class TestCargoAuditAdapter:
    def test_is_available_returns_true_when_installed(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which",
            lambda x: "/usr/bin/cargo-audit" if x == "cargo-audit" else None,
        )
        adapter = CargoAuditAdapter()
        assert adapter.is_available() is True

    def test_is_available_returns_false_when_not_installed(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        adapter = CargoAuditAdapter()
        assert adapter.is_available() is False

    @pytest.mark.asyncio
    async def test_run_parses_vulnerabilities_list(self, monkeypatch):
        stdout_data = {
            "vulnerabilities": {
                "list": [
                    {
                        "package_name": "serde",
                        "affected_version": "1.0.100",
                        "title": "Buffer overflow in deserialization",
                        "description": "A buffer overflow can occur...",
                        "severity": "High",
                    },
                    {
                        "package_name": "hyper",
                        "affected_version": "0.14.0",
                        "title": "HTTP request smuggling",
                        "description": "HTTP/1 request smuggling...",
                        "severity": "Medium",
                    },
                ]
            }
        }
        mock_stdout = json.dumps(stdout_data)

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = CargoAuditAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("/path/to/project")

        assert len(findings) == 2
        assert findings[0].title == "Cargo Audit: Buffer overflow in deserialization"
        assert findings[0].location == "serde@1.0.100"
        assert findings[0].severity == "High"

    @pytest.mark.asyncio
    async def test_run_parses_advisories_format(self, monkeypatch):
        stdout_data = {
            "advisories": {
                "RUSTSEC-2023-0001": {
                    "package_name": "chrono",
                    "package_version": "0.4.0",
                    "summary": "Potential segfault in localtime_r invocations",
                    "details": "A segfault can occur...",
                    "severity": "High",
                },
                "RUSTSEC-2023-0002": {
                    "package_name": "time",
                    "package_version": "0.3.0",
                    "summary": "Potential segfault in time crate",
                    "details": "Another segfault issue...",
                },
            }
        }
        mock_stdout = json.dumps(stdout_data)

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = CargoAuditAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("/path/to/project")

        assert len(findings) == 2
        assert any("chrono" in f.location for f in findings)
        assert any("time" in f.location for f in findings)

    @pytest.mark.asyncio
    async def test_run_handles_no_vulnerabilities(self, monkeypatch):
        stdout_data = {"vulnerabilities": {"list": []}}
        mock_stdout = json.dumps(stdout_data)

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = CargoAuditAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("/path/to/project")

        assert len(findings) == 1
        assert findings[0].severity == "Info"
        assert "no vulnerable" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_run_handles_invalid_json(self, monkeypatch):
        mock_stdout = "Not valid JSON output"

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 1

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = CargoAuditAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("/path/to/project")

        assert len(findings) == 1
        assert findings[0].severity == "Info"

    @pytest.mark.asyncio
    async def test_run_handles_cvss_score(self, monkeypatch):
        stdout_data = {
            "vulnerabilities": {
                "list": [
                    {
                        "package_name": "openssl",
                        "package_version": "0.10.0",
                        "title": "Certificate validation bypass",
                        "description": "CVE-2023-XXXXX",
                        "cvssV3": {"score": 9.8},
                    }
                ]
            }
        }
        mock_stdout = json.dumps(stdout_data)

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = CargoAuditAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("/path/to/project")

        assert len(findings) == 1
        assert findings[0].severity == "9.8"


class TestCargoAuditAdapterIntegration:
    """Integration tests with real cargo-audit if available."""

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        not CargoAuditAdapter().is_available(),
        reason="cargo-audit not installed",
    )
    async def test_integration_with_real_cargo_audit(self, tmp_path):
        import os

        original_dir = os.getcwd()
        os.chdir(tmp_path)

        try:
            (tmp_path / "Cargo.toml").write_text(
                """
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
"""
            )

            adapter = CargoAuditAdapter()
            findings = await adapter.run(str(tmp_path))

            assert isinstance(findings, list)
            assert all(isinstance(f, Finding) for f in findings)

        finally:
            os.chdir(original_dir)
