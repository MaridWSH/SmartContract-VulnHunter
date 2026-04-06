# CI Guardrails and Governance

## Overview
This document defines the guardrails for the SC-CLI CI pipeline to ensure reliability and prevent regressions.

## Gate Ownership and Responsibilities

| Gate | Owner | Contact | Escalation Path |
|------|-------|---------|-----------------|
| **Lint** | Auto-enforced | N/A | Fix and re-push |
| **Type Check** | Auto-enforced | N/A | Fix and re-push |
| **Security** | Security Team | #security | 24h SLA for false positives |
| **Test** | QA Lead | #qa | 48h investigation |
| **Coverage** | Tech Lead | #tech-lead | Weekly review if blocking |
| **Packaging** | Release Engineer | #release | 24h fix SLA |

## Rollback Procedures

### When to Rollback
- CI gates cause >10% PR blockage rate for 1 week
- Critical security vulnerability in dependency
- Flaky tests causing >5% false failure rate
- CI duration exceeds 15 minutes consistently

### Immediate Rollback (15 minutes)

**Owner**: CI Engineer

```bash
# Step 1: Lower threshold temporarily
sed -i 's/--cov-fail-under=50/--cov-fail-under=40/g' .github/workflows/ci.yml

# Step 2: Commit with clear message
git add .github/workflows/ci.yml
git commit -m "ROLLBACK: Lower coverage threshold due to gate blockage

Trigger: >10% of PRs failing coverage gate
Previous: --cov-fail-under=50
Current: --cov-fail-under=40
Remediation Ticket: CI-XXX (create now)
Owner: Tech Lead"

# Step 3: Push to main (requires admin if gates still failing)
git push origin main

# Step 4: Notify
# Post in #dev-ci: 
# "🚨 CI GATE ROLLBACK: Coverage threshold lowered 50%→40% due to blockage.
#    Remediation: CI-XXX. ETA to restore: 1 week."
```

### Short-term Remediation (24 hours)

**Owner**: Tech Lead

1. **Create ticket** with:
   ```markdown
   ## CI Gate Remediation
   - Gate: Coverage
   - Current: 40% (rolled back from 50%)
   - Target: 50%
   - Root Cause: [To be investigated]
   - Test Plan: [List missing tests]
   - Owner: [Assignee]
   - Deadline: [1 week from now]
   ```

2. **Assign owner** and set deadline
3. **Schedule daily standup** check-ins until resolved

### Long-term Resolution (1 week)

**Owner**: Tech Lead

1. Add missing tests to reach original threshold
2. Re-enable stricter gate:
   ```bash
   sed -i 's/--cov-fail-under=40/--cov-fail-under=50/g' .github/workflows/ci.yml
   git commit -m "Restore coverage threshold to 50% (remediation complete)"
   ```
3. Post-mortem if significant impact

### Emergency Override

For critical hotfixes when gates are blocking:

```bash
# Option 1: Admin bypass (preferred)
# GitHub: Settings > Branches > main > Edit protection rules
# Temporarily uncheck "Require status checks to pass"
# Merge critical PR
# Immediately re-enable protection

# Option 2: Skip CI (discouraged, requires written approval)
git commit -m "HOTFIX: Critical security patch [skip ci]

Override approved by: [Tech Lead name]
Ticket: INCIDENT-XXX
Follow-up: Fix tests within 4 hours"

# REQUIRED: Create follow-up ticket within 1 hour
```

## Flaky Test Guardrails

### Detection
- Tests that fail intermittently will be marked with `@pytest.mark.flaky`
- CI will retry flaky tests up to 3 times before marking as failed
- Flaky test reports are uploaded as artifacts

### Mitigation
- Use deterministic mocks for external dependencies
- Avoid network calls in unit tests
- Use `time.sleep` only when absolutely necessary

## Timeout Guardrails

### Job Timeouts
- Lint job: 5 minutes
- Security job: 5 minutes
- Test job: 10 minutes per Python version
- E2E job: 5 minutes
- Packaging job: 5 minutes

### Step Timeouts
- Install dependencies: 2 minutes
- Run tests: 8 minutes
- Build package: 3 minutes

## Environmental Dependencies

### Pinned Versions
- Python: 3.11, 3.12 (matrix)
- All dependencies pinned in pyproject.toml
- Dev dependencies explicitly versioned
- Cache keyed by pyproject.toml hash

### External Binaries
The following adapters require external binaries that may not be available in CI:
- EchidnaAdapter (requires `echidna`)
- FoundryAdapter (requires `forge`)
- MedusaAdapter (requires `medusa`)

**Mitigation**: Tests for these adapters use mocks when binaries are unavailable.

## Gating Rules

### PR Requirements (Must Pass)
1. ✅ All lint checks pass (ruff, black, mypy) - **Auto-enforced**
2. ✅ All tests pass (or skip with valid reason) - **QA**
3. ✅ Coverage ≥ 50% (phased: 50% → 65% → 85%) - **Tech Lead**
4. ✅ Security scan complete (non-blocking for now) - **Security**
5. ✅ Packaging succeeds - **Release Eng**

### Merge Requirements
1. ✅ PR requirements met
2. ✅ Two reviewer approvals (Senior + Peer)
3. ✅ No outstanding review comments
4. ✅ Branch up to date with main

## Monitoring

### Metrics to Track
| Metric | Target | Alert Threshold | Owner |
|--------|--------|-----------------|-------|
| Test pass rate | >99% | <95% | QA |
| CI duration | <5 min | >10 min | CI Eng |
| Coverage trend | Increasing | Flat 2 weeks | Tech Lead |
| Flaky test count | 0 | >3 | QA |
| PR blockage rate | <5% | >10% | Tech Lead |

### Alert Channels
- Slack: #dev-ci for CI issues
- Slack: #security for vulnerability alerts
- Email: tech-leads@ for coverage/blockage issues

## Reproducible Builds

### Build Verification
- SHA256 checksums generated for all artifacts
- Checksums stored in `dist/checksums.txt`
- Artifacts uploaded with provenance metadata

### Cache Strategy
- pip cache keyed by pyproject.toml
- Cache version: `v1` (bump if needed)
- Cache hit reduces install time by ~60%

## Incident Response

### Severity Levels
- **P0**: All PRs blocked, main branch broken → Immediate response
- **P1**: Specific gate failing >20% of PRs → 4h response
- **P2**: Performance degradation → 24h response
- **P3**: Documentation gaps → Weekly triage

### Response Team
- **P0/P1**: CI Engineer + Tech Lead
- **P2**: CI Engineer
- **P3**: Any team member

---

**Last Updated**: 2026-03-25
**Location**: `docs/ci/guardrails.md` (versioned with repo)
