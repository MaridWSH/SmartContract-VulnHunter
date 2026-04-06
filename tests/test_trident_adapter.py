"""Tests for TridentAdapter."""

import json
from typing import List

import pytest

from vulnhunter.adapters.trident_adapter import TridentAdapter
from vulnhunter.findings import Finding


class TestTridentAdapter:
    def test_is_available_returns_true_when_installed(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which", lambda x: "/usr/bin/trident" if x == "trident" else None
        )
        adapter = TridentAdapter()
        assert adapter.is_available() is True

    def test_is_available_returns_false_when_not_installed(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        adapter = TridentAdapter()
        assert adapter.is_available() is False

    @pytest.mark.asyncio
    async def test_run_parses_json_crashes(self, monkeypatch):
        stdout_data = [
            {"crash": "Arithmetic overflow in transfer", "location": "lib.rs:42"},
            {"crash": "Divide by zero", "location": "math.rs:15"},
        ]
        mock_stdout = json.dumps(stdout_data)

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = TridentAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("target_program")

        assert len(findings) == 2
        assert findings[0].title == "Trident crash"
        assert findings[0].severity == "High"

    @pytest.mark.asyncio
    async def test_run_parses_text_crashes(self, monkeypatch):
        mock_stdout = """
Fuzzing session started...
[CRASH] Panic at 'index out of bounds' in lib.rs:123
[CRASH] Segfault detected
Fuzzing completed.
"""

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = TridentAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("target_program")

        crash_findings = [f for f in findings if f.title == "Trident crash"]
        assert len(crash_findings) == 2

    @pytest.mark.asyncio
    async def test_run_handles_timeout(self, monkeypatch):
        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    raise asyncio.TimeoutError()

                def kill(self):
                    pass

                async def wait(self):
                    return 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = TridentAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("target_program")

        assert len(findings) == 1
        assert "timeout" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_run_returns_info_when_no_crashes(self, monkeypatch):
        mock_stdout = "Fuzzing completed successfully with no crashes found."

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = TridentAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("target_program")

        assert len(findings) == 1
        assert findings[0].severity == "Info"


class TestTridentAdapterAnchorSupport:
    """Tests specific to Anchor program fuzzing support."""

    @pytest.mark.asyncio
    async def test_detects_anchor_specific_panics(self, monkeypatch):
        mock_stdout = """
[ANCHOR] Program invoked an instruction with invalid accounts
[CRASH] Panic: AccountNotInitialized
[CRASH] Exception: Invalid owner
"""

        async def mock_subprocess(*args, **kwargs):
            class MockProc:
                async def communicate(self):
                    return mock_stdout.encode(), b""

                returncode = 0

            return MockProc()

        monkeypatch.setattr("asyncio.create_subprocess_exec", mock_subprocess)
        adapter = TridentAdapter()
        monkeypatch.setattr(adapter, "is_available", lambda: True)

        findings = await adapter.run("anchor_program")

        crash_findings = [
            f
            for f in findings
            if "Crash" in f.title or "panic" in f.description.lower()
        ]
        assert len(crash_findings) >= 2
