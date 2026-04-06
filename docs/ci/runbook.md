# SC-CLI CI/CD Runbook

## Quick Start for New Contributors

### Local Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd SC-CLI

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pip install pre-commit
pre-commit install
```

### Running Tests Locally

```bash
# Run all tests
pytest

# Run with coverage (must pass 50% gate)
pytest --cov=src --cov-fail-under=50

# Run specific test suites
pytest tests/adapters/ -v
pytest tests/e2e/ -v

# Run linting
ruff check src/
black --check src/
mypy src/

# Run pre-commit on all files
pre-commit run --all-files
```

### Understanding CI Gates

When you open a PR, these gates must pass:

| Gate | Tool | Requirement | Owner |
|------|------|-------------|-------|
| **Lint** | Ruff + Black | 0 errors | Auto-enforced |
| **Type Check** | MyPy | 0 errors | Auto-enforced |
| **Security** | Bandit + pip-audit | No HIGH/CRITICAL | Security team |
| **Test** | pytest | All tests pass | QA |
| **Coverage** | pytest-cov | ≥ 50% (phased to 85%) | Tech Lead |
| **Packaging** | build + twine | Clean build | Release eng |

## Rollback Procedures

### When to Rollback CI Gates

**Trigger**: CI gates causing >10% PR blockage rate for 1 week

**Immediate Actions** (CI Engineer - 15 minutes):
```bash
# 1. Edit ci.yml to lower threshold temporarily
sed -i 's/--cov-fail-under=50/--cov-fail-under=40/g' .github/workflows/ci.yml

# 2. Commit with clear message
git add .github/workflows/ci.yml
git commit -m "HOTFIX: Lower coverage threshold due to gate blockage

Context: >10% of PRs failing coverage gate
Action: Temporarily lowering from 50% to 40%
Ticket: CI-XXX (create immediately)"

# 3. Push to main (requires admin override)
git push origin main

# 4. Notify team
# Post in #dev-ci: "Coverage gate temporarily lowered. See CI-XXX for details."
```

**Short-term Actions** (Tech Lead - 24 hours):
1. Create remediation ticket with:
   - Root cause analysis
   - Test addition plan
   - Target date to re-enable gate
2. Assign owner
3. Set deadline

**Long-term Actions** (Tech Lead - 1 week):
1. Add missing tests to reach threshold
2. Re-enable stricter gate
3. Post-mortem if significant impact

### Emergency Override

For critical hotfixes when gates are blocking:

```bash
# Option 1: Use [skip ci] (discouraged, requires admin)
git commit -m "HOTFIX: Critical security patch [skip ci]"

# Option 2: Admin bypass (preferred)
# GitHub: Settings > Branches > main > Uncheck "Require status checks"
# Merge PR
# Immediately re-enable checks

# Required follow-up (within 1 hour):
# - Create ticket to fix underlying issue
# - Tech Lead approval documented
```

### Common Failure Modes

#### "Coverage below 50%"
**Cause**: Your changes reduced test coverage
**Fix**: Add tests for new code
```bash
# Check which lines are uncovered
pytest --cov=src --cov-report=term-missing

# Add tests, then verify
pytest --cov=src --cov-fail-under=50
```

#### "Ruff check failed"
**Cause**: Code style violations
**Fix**: Run auto-fix
```bash
ruff check --fix src/
black src/
git add -A
git commit -m "Fix linting issues"
```

#### "MyPy error"
**Cause**: Type annotation issues
**Fix**: Check type hints
```python
# Wrong
def process(data):
    return data + 1

# Right
def process(data: int) -> int:
    return data + 1

# Or if truly dynamic
from typing import Any
def process(data: Any) -> Any:  # type: ignore
    return data + 1
```

#### "Test skipped due to missing binary"
**Info**: Echidna, Foundry, or Medusa not installed
**Options**:
1. Install the binary locally for full testing
2. Rely on mocked unit tests (sufficient for most PRs)
3. Run in CI where binaries may be available

### CI Job Dependencies

```
lint ──────────────────────────────┐
                                   ├──► packaging
security ──────────────────────────┤   (needs all)
                                   │
test (3.11) ────┐                  │
                ├──► end-to-end ───┘
test (3.12) ────┘   (needs lint + test)
```

### Coverage Improvement Plan

| Phase | Target | Timeline | Focus Area | Exit Criteria |
|-------|--------|----------|------------|---------------|
| 1 | 50% | Current | Adapter mocking | All adapter tests passing |
| 2 | 65% | 2-4 weeks | Core orchestrator | Orchestrator coverage >50% |
| 3 | 85% | Monthly | Edge cases | Error paths tested |

### External Binary Dependencies

These adapters need external tools (tests skip if unavailable):

| Adapter | Binary | Installation | CI Strategy |
|---------|--------|--------------|-------------|
| EchidnaAdapter | echidna | `brew install echidna` | Mocked in unit tests |
| FoundryAdapter | forge | `curl -L https://foundry.paradigm.xyz \| bash` | Mocked in unit tests |
| MedusaAdapter | medusa | Build from source | Mocked in unit tests |

### Artifact Locations

After CI completes:
- Coverage reports: `coverage-report-*.xml`
- Security scans: `bandit-report.json`, `pip-audit-report.json`
- Build artifacts: `dist/` (wheel + sdist + checksums.txt)

### Getting Help

1. **Check this runbook first** (you are here)
2. **Review docs/ci/guardrails.md** for gate details
3. **Ask in #dev-ci Slack channel** for quick questions
4. **Escalate to Tech Lead** if gates seem unfair or broken

### Success Metrics

| Metric | Target | Alert Threshold | Owner |
|--------|--------|-----------------|-------|
| Test pass rate | >99% | <95% | QA Lead |
| CI duration | <5 min | >10 min | CI Engineer |
| Coverage trend | Increasing | Flat 2 weeks | Tech Lead |
| PR blockage rate | <5% | >10% | Tech Lead |

---

**Last Updated**: 2026-03-25
**Maintained by**: CI Engineer
**Location**: `docs/ci/runbook.md` (versioned with repo)
