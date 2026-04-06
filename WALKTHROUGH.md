# SmartContract VulnHunter Framework - Complete Walkthrough

**Ultimate smart contract security CLI framework for bug bounty researchers**

---

## 📁 Project Structure

```
/home/ubuntu/SC-CLI/
├── src/vulnhunter/
│   ├── adapters/          # 15 scanner adapters
│   │   ├── slither_adapter.py
│   │   ├── aderyn_adapter.py
│   │   ├── solhint_adapter.py
│   │   ├── semgrep_adapter.py
│   │   ├── fournaly3er_adapter.py
│   │   ├── mythril_adapter.py
│   │   ├── echidna_adapter.py
│   │   ├── medusa_adapter.py
│   │   ├── foundry_adapter.py
│   │   ├── heimdall_adapter.py
│   │   ├── trident_adapter.py
│   │   ├── sec3_xray_adapter.py
│   │   ├── cargo_audit_adapter.py
│   │   ├── caracal_adapter.py
│   │   └── vyper_adapter.py
│   ├── commands/          # 5 CLI commands
│   │   ├── scan.py
│   │   ├── clone.py
│   │   ├── report.py
│   │   ├── config.py
│   │   └── bounty.py
│   ├── config/            # Settings & plugins
│   │   ├── settings.py
│   │   └── plugin_system.py
│   ├── core/              # Orchestration engine
│   │   ├── orchestrator.py
│   │   ├── sarif_merger.py
│   │   ├── deduplicator.py
│   │   ├── repo_cloner.py
│   │   ├── task.py
│   │   └── results_store.py
│   ├── llm/               # Kimi K2.5 integration
│   │   ├── client.py
│   │   ├── pipeline.py
│   │   └── prompts.py
│   ├── models/            # Data models
│   │   ├── finding.py
│   │   ├── sarif.py
│   │   └── fingerprint.py
│   ├── poc/               # PoC generation
│   │   ├── generator.py
│   │   ├── executor.py
│   │   └── templates/
│   │       ├── reentrancy.t.sol.j2
│   │       ├── flash_loan.t.sol.j2
│   │       ├── oracle_manipulation.t.sol.j2
│   │       └── access_control.t.sol.j2
│   ├── reporters/         # Platform reporters
│   │   ├── immunefi.py
│   │   ├── code4rena.py
│   │   ├── sherlock.py
│   │   └── codehawks.py
│   ├── main.py            # Entry point
│   └── __main__.py        # Module execution
├── tests/
│   └── test_end_to_end.py # Integration test
├── pyproject.toml         # Package config
├── .github/workflows/ci.yml
├── README.md
└── USAGE.md
```

---

## 🔧 Core Architecture

### 1. Multi-Language Scanner Support (15 Adapters)

| Language | Count | Tools |
|----------|-------|-------|
| **Solidity** | 10 | Slither, Aderyn, Solhint, Semgrep, 4naly3er, Mythril, Echidna, Medusa, Foundry, Heimdall |
| **Rust/Solana** | 3 | Trident, sec3 X-ray, cargo-audit |
| **Vyper** | 1 | Slither-backed |
| **Cairo** | 1 | Caracal |

### 2. Async Orchestration Engine

**Components:**

- **Orchestrator** (`core/orchestrator.py`): Manages concurrent scanner execution with semaphore-based concurrency (default: 5 parallel tasks)
- **SARIF Merger** (`core/sarif_merger.py`): Normalizes output from all tools into unified SARIF 2.1.0 format
- **Deduplicator** (`core/deduplicator.py`): Fingerprint-based duplicate removal across tools (rule_id + file + line hash)
- **Results Store** (`core/results_store.py`): Persistent JSON storage with restart capability
- **Repo Cloner** (`core/repo_cloner.py`): GitPython-based repository cloning with language detection

### 3. LLM Pipeline (Kimi K2.5)

**6-Pass Analysis:**

1. **Protocol Understanding** - Maps protocol architecture and key components
2. **Attack Surface Mapping** - Identifies all potential entry points
3. **Invariant Violation Analysis** - Finds logic errors and broken invariants
4. **Cross-Function Interaction** - Analyzes inter-contract calls and dependencies
5. **Adversarial Modeling** - Simulates attacker strategies
6. **Boundary & Edge Cases** - Tests limits and unusual conditions

**Features:**
- OpenAI-compatible API (`https://api.moonshot.ai/v1`)
- Context caching (75% cost reduction for repeated analyses)
- 256K context window
- Function calling support for tool orchestration

### 4. PoC Generation

**Templates:**
- **Reentrancy** - Classic reentrancy attack patterns
- **Flash Loan** - Flash loan exploitation vectors
- **Oracle Manipulation** - Price oracle manipulation scenarios
- **Access Control** - Privilege escalation patterns

**Workflow:**
1. LLM analyzes finding and generates Foundry test
2. Template engine fills vulnerability-specific parameters
3. PoC Executor runs `forge test --json` to validate
4. Failed tests trigger iterative refinement

### 5. Platform-Specific Reporting

**Immunefi:**
- Funds-at-risk calculation (tokens × price)
- Foundry fork tests required for PoC
- Severity: Critical/High/Medium/Low

**Code4rena:**
- High/Medium findings: Individual submissions
- Low/QA findings: Single compiled report per warden
- Award split formula: `10 * (0.85^(split-1)) / split`

**Sherlock:**
- Impact-based severity only (no likelihood)
- Lead Senior Watson + competitive audit
- Real-time judging with signal scoring

**Codehawks:**
- Impact × Likelihood severity matrix
- Gas/QA findings excluded (as of Aug 2023)
- 85% invalid threshold for disqualification

---

## 🚀 CLI Workflow

### Step 1: Installation & Setup

```bash
# Clone and install
cd /home/ubuntu/SC-CLI
pip install -e .

# Initialize configuration
vulnhunter config init
# Creates vulnhunter.toml with default settings
```

### Step 2: Clone Target Repository

```bash
# Clone a smart contract repo
vulnhunter clone repo https://github.com/example/defi-protocol.git \
  --branch main \
  --output ./targets/defi-protocol

# Framework auto-detects language based on file extensions:
# - Solidity: .sol files
# - Rust/Solana: .rs files + Cargo.toml
# - Vyper: .vy files
# - Cairo: .cairo files
```

### Step 3: Run Security Scan

```bash
# Scan with all available tools
vulnhunter scan run ./targets/defi-protocol \
  --output ./results \
  --parallel 5 \
  --timeout 300

# Or specify specific tools
vulnhunter scan run ./targets/defi-protocol \
  --tools slither,aderyn,mythril \
  --output ./results

# Options:
#   --parallel N      Max concurrent tasks (default: 5)
#   --timeout SECS    Per-tool timeout (default: 300)
#   --tools LIST      Comma-separated tool names
```

**What happens during scan:**
1. Orchestrator detects available tools via `is_available()`
2. Creates async tasks for each tool with semaphore limiting
3. Runs tools in parallel (max concurrent controlled by `--parallel`)
4. Collects SARIF/JSON output from each tool
5. SARIF Merger normalizes all outputs to unified format
6. Deduplicator removes duplicates by fingerprint (rule_id + file + line)
7. Saves to `./results/findings.json`

### Step 4: LLM Deep Analysis (Automatic in Pipeline)

```python
from vulnhunter.llm.pipeline import AnalysisPipeline
from vulnhunter.llm.client import KimiClient

# Initialize client
client = KimiClient(api_key="YOUR_API_KEY")
pipeline = AnalysisPipeline(client=client)

# Run 6-pass analysis
results = await pipeline.analyze_findings(
    findings=findings,
    code=contract_code
)

# Extracts:
# - Protocol invariants and constraints
# - Cross-contract attack paths
# - Exploitability assessment
# - PoC generation hints
# - Remediation recommendations
```

### Step 5: Generate PoC

```python
from vulnhunter.poc.generator import PoCGenerator
from vulnhunter.poc.executor import PoCExecutor

# Generate Foundry test
generator = PoCGenerator()
poc_code = generator.generate_test(
    finding=finding,
    contract_code=source_code,
    template="reentrancy"  # or: flash_loan, oracle, access_control
)

# Validate PoC
executor = PoCExecutor()
result = await executor.run_test(
    test_code=poc_code,
    project_dir=target_dir
)

# If validation fails, iterates with LLM to fix
```

### Step 6: Create Submission Report

```bash
# Generate platform-specific report
vulnhunter report generate ./results \
  --platform immunefi \
  --format markdown \
  --output report.md

# Options:
#   --platform {immunefi,code4rena,sherlock,codehawks}
#   --format {markdown,json,pdf}
#   --output PATH

# Or prepare bounty submission with PoC
vulnhunter bounty prepare ./results/findings.json \
  --platform code4rena \
  --poc ./pocs/Exploit.t.sol \
  --output submission.md
```

**Report includes:**
- Platform-specific severity classification
- Impact calculation (funds at risk for Immunefi)
- Formatted PoC code blocks
- Remediation suggestions
- References to similar vulnerabilities
- Compliance with platform submission rules

---

## 🔄 Complete End-to-End Workflow Example

```bash
# 1. Setup - create config file
vulnhunter config init --path ./vulnhunter.toml

# 2. Clone target repository
vulnhunter clone repo https://github.com/target/protocol.git \
  --output ./protocol \
  --branch main

# 3. Run comprehensive scan (orchestrates all 15+ tools)
vulnhunter scan run ./protocol \
  --output ./results \
  --parallel 5 \
  --timeout 600

# 4. Review findings
jq '.[] | {title: .title, severity: .severity, tool: .tool}' ./results/findings.json

# 5. Generate platform report (example: Immunefi)
vulnhunter report generate ./results \
  --platform immunefi \
  --format markdown \
  --output ./report-immunefi.md

# 6. Prepare bounty submission with PoC
vulnhunter bounty prepare ./results/findings.json \
  --platform immunefi \
  --poc ./poc/Exploit.t.sol \
  --output ./bounty-submission.md
```

---

## 📊 Data Flow Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Repository    │────▶│   Repo Cloner    │────▶│  Language Detect │
│   (Git URL)     │     │  (GitPython)     │     │ (Solidity/Rust/  │
└─────────────────┘     └──────────────────┘     │  Vyper/Cairo)    │
                                                  └─────────────────┘
                                                           │
                              ┌────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Scanner Orchestrator                         │
│                    (Async + Semaphore)                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐  │
│  │   Slither   │ │   Aderyn    │ │   Mythril   │ │  Echidna │  │
│  │  (Library)  │ │ (Subprocess)│ │(Subprocess) │ │(Subproc) │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐  │
│  │   Solhint   │ │   Semgrep   │ │   Foundry   │ │  Medusa  │  │
│  │(Subprocess) │ │ (SARIF out) │ │(Subprocess) │ │(Subproc) │  │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   Trident   │ │ sec3 X-ray  │ │cargo-audit  │              │
│  │  (Solana)   │ │  (Solana)   │ │   (Rust)    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  SARIF Merger   │────▶│  Deduplicator    │────▶│  Findings Store │
│ (Normalize all  │     │ (Fingerprint-based│     │  (JSON/SARIF)   │
│  tool outputs)  │     │  duplicate removal)│    │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LLM Analysis Pipeline                         │
│              (Kimi K2.5 - 6 Pass Analysis)                       │
│                                                                  │
│  Pass 1: Protocol Understanding                                │
│  Pass 2: Attack Surface Mapping                                │
│  Pass 3: Invariant Violation Analysis                          │
│  Pass 4: Cross-Function Interaction                            │
│  Pass 5: Adversarial Modeling                                  │
│  Pass 6: Boundary & Edge Cases                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  PoC Generator  │────▶│  Foundry Exec    │────▶│  Report Gen     │
│ (Foundry tests) │     │ (forge test)     │     │ (Platform-spec) │
│  + Templates    │     │  Validation      │     │  Formatting     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                           │
                              ┌────────────────────────────┘
                              ▼
                  ┌─────────────────────┐
                  │  Platform Reports   │
                  │ • Immunefi          │
                  │ • Code4rena         │
                  │ • Sherlock          │
                  │ • Codehawks         │
                  └─────────────────────┘
```

---

## 🎯 Key Features

1. **Multi-Chain Support**
   - Native adapters for Solidity, Rust/Solana, Vyper, Cairo
   - Automatic language detection from file extensions

2. **Smart Orchestration**
   - Async parallel execution with configurable concurrency
   - Semaphore-based resource limiting
   - Restartable scans (persistent state)

3. **SARIF Standard**
   - All tools normalized to SARIF 2.1.0
   - Interoperability with existing security tooling
   - Standardized severity mapping

4. **LLM Integration**
   - Kimi K2.5 with cost-efficient context caching (75% reduction)
   - 6-pass deep analysis mirroring professional auditor workflow
   - OpenAI-compatible API for easy integration

5. **PoC Auto-Generation**
   - Foundry-based exploit generation
   - Automatic validation with `forge test`
   - Iterative refinement on test failures

6. **Platform Awareness**
   - Bug bounty specific report formats
   - Severity rules per platform
   - Submission-ready templates

7. **Extensible Architecture**
   - Plugin system via `pluggy`
   - Easy adapter development
   - Custom reporter support

---

## ✅ Verification Status

| Check | Command | Status |
|-------|---------|--------|
| **Package Installation** | `pip install -e .` | ✅ Pass |
| **CLI Operation** | `vulnhunter --help` | ✅ Pass |
| **End-to-End Test** | `python tests/test_end_to_end.py` | ✅ Pass |
| **File Count** | 51 Python files | ✅ Pass |
| **Adapter Count** | 15 adapters | ✅ Pass |
| **CI/CD** | `.github/workflows/ci.yml` | ✅ Configured |
| **Documentation** | `USAGE.md`, `README.md` | ✅ Complete |

---

## 📚 Usage Examples

### Basic Scan
```bash
vulnhunter scan run ./my-contracts -o ./results
```

### Multi-Tool Scan with Timeout
```bash
vulnhunter scan run ./protocol \
  --tools slither,mythril,aderyn \
  --parallel 3 \
  --timeout 600 \
  --output ./results
```

### Generate Platform Report
```bash
# For Immunefi (funds-at-risk focused)
vulnhunter report generate ./results --platform immunefi -o report.md

# For Code4rena (competitive audit)
vulnhunter report generate ./results --platform code4rena -o report.md

# For Sherlock (impact-based)
vulnhunter report generate ./results --platform sherlock -o report.md

# For Codehawks (matrix-based)
vulnhunter report generate ./results --platform codehawks -o report.md
```

### Clone Private Repo with Token
```bash
vulnhunter clone repo https://github.com/private/repo.git \
  --token $GITHUB_TOKEN \
  --output ./targets/private
```

---

## 🔐 Security Considerations

1. **API Keys**: Store LLM API keys in environment variables (`VULNHUNTER_LLM__API_KEY`)
2. **Private Repos**: Use tokens for authentication, never commit credentials
3. **PoC Safety**: All generated PoCs should be tested in isolated environments
4. **Tool Versions**: Pin external tool versions for reproducible results

---

## 🚀 Production Readiness

The framework is **verified and ready** for a solo bug bounty researcher to:

1. ✅ Clone target repositories (public/private)
2. ✅ Run 15+ security scanners in parallel
3. ✅ Feed results to LLM for deep analysis
4. ✅ Generate validated PoC exploits
5. ✅ Produce submission-ready reports for major platforms

**Location:** `/home/ubuntu/SC-CLI`

**Install:** `pip install -e .`

**Test:** `python tests/test_end_to_end.py`

---

## 📖 Additional Resources

- **README.md** - Project overview and quick start
- **USAGE.md** - Detailed command reference
- **pyproject.toml** - Package configuration and dependencies
- **.github/workflows/ci.yml** - CI/CD pipeline

---

*Built with Python 3.11+, Typer, Rich, Pydantic, and asyncio*
