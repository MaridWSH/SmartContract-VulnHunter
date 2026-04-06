# SmartContract VulnHunter OpenCode Integration

SmartContract VulnHunter is now integrated with OpenCode via MCP (Model Context Protocol), allowing you to orchestrate 15+ security scanners directly from OpenCode.

## ✅ Integration Status

**MCP Server**: `vulnhunter` - Connected ✅

## 🚀 Available MCP Tools

| Tool | Description | Example Usage |
|------|-------------|---------------|
| `vulnhunter-scan` | Scan smart contracts with multiple tools | `"Scan /path/to/contracts with vulnhunter"` |
| `vulnhunter-clone` | Clone a repository for analysis | `"Clone https://github.com/org/repo.git"` |
| `vulnhunter-recon` | Perform reconnaissance | `"Run recon on /path/to/project"` |
| `vulnhunter-analyze` | Deep LLM analysis | `"Analyze findings at /path/to/findings.json"` |
| `vulnhunter-poc` | Generate PoC exploits | `"Generate PoC for findings.json"` |
| `vulnhunter-report` | Generate platform reports | `"Generate Code4rena report for results"` |
| `vulnhunter-bounty` | Prepare bounty submission | `"Prepare Immunefi submission"` |
| `vulnhunter-hunt` | Automated hunting workflow | `"Hunt for vulnerabilities in /path"` |
| `vulnhunter-audit` | Full audit workflow | `"Run full audit on /path/to/project"` |
| `vulnhunter-status` | Check status | `"Show vulnhunter status"` |

## 📋 Example Commands in OpenCode

### Scan Smart Contracts
```
"Scan the contracts at /home/ubuntu/my-project with vulnhunter"
"Run vulnhunter scan on ./src with slither and aderyn"
"Scan /path/to/contracts with all tools, output to ./results"
```

### Clone and Analyze
```
"Clone https://github.com/example/defi-protocol.git and scan it"
"Clone repo https://github.com/org/contracts then run vulnhunter"
```

### Reconnaissance
```
"Run vulnhunter recon on /path/to/project"
"Perform reconnaissance on ./contracts and save to recon.md"
```

### LLM Analysis
```
"Analyze the findings at ./vulnhunter-results/findings.json"
"Run deep analysis on scan results"
```

### PoC Generation
```
"Generate PoC exploits for findings.json"
"Create reentrancy PoC for the findings"
```

### Platform Reports
```
"Generate an Immunefi report from ./vulnhunter-results"
"Create Code4rena report for findings"
"Prepare Sherlock submission from scan results"
```

### Bounty Submissions
```
"Prepare bounty submission for Immunefi"
"Generate Code4rena submission from findings.json"
```

### Automated Hunting
```
"Hunt for vulnerabilities in /path/to/project"
"Run deep hunt on https://github.com/org/repo"
```

### Full Audit
```
"Run full vulnhunter audit on /path/to/contracts"
"Perform end-to-end audit workflow"
```

## 🔧 Supported Scanners

### Solidity (10 adapters)
- Slither
- Aderyn
- Solhint
- Semgrep
- 4naly3er
- Mythril
- Echidna
- Medusa
- Foundry
- Heimdall

### Rust/Solana (3 adapters)
- Trident
- sec3 X-ray
- cargo-audit

### Vyper (1 adapter)
- Slither-backed

### Cairo (1 adapter)
- Caracal

## 📝 Workflow Examples

### Complete Bug Bounty Workflow
```
1. "Clone https://github.com/target/protocol.git to ./target"
2. "Run vulnhunter scan on ./target --tools slither,aderyn,mythril"
3. "Analyze the findings with vulnhunter"
4. "Generate PoC for critical findings"
5. "Generate Immunefi report from results"
6. "Prepare bounty submission"
```

### Quick Audit
```
"Run vulnhunter audit on /path/to/project"
```

### Deep Analysis
```
"Hunt for vulnerabilities in /path with deep scan"
"Analyze findings and generate PoC"
"Prepare Code4rena report"
```

## 🔧 Configuration

SmartContract VulnHunter configuration is at `/home/ubuntu/SC-CLI/vulnhunter.toml`:

```toml
[vulnhunter]
debug = false

[vulnhunter.scan]
timeout = 600
max_retries = 5
threads = 8

[vulnhunter.llm]
api_key = "your-api-key"
model = "moonshotai/kimi-k2.5"
base_url = "https://openrouter.ai/api/v1"
```

## 📊 Integration with Other MCP Servers

SmartContract VulnHunter works alongside other security MCP servers:

| Server | Use Case |
|--------|----------|
| `vulnhunter` | Smart contract audits (15+ scanners) |
| `slither` | Direct Slither static analysis |
| `nuclei` | Web vulnerability scanning |
| `nmap` | Network scanning |
| `ffuf` | Web fuzzing |

### Combined Workflow Example
```
# Smart contract audit
"Scan contracts with vulnhunter"

# Web app testing  
"Scan the dapp frontend with nuclei"

# Network security
"Scan the API server with nmap"
```

## 🛠️ MCP Server Location

```
~/.opencode/mcp-servers/vulnhunter-mcp/
├── src/
│   └── index.ts          # MCP server source
├── build/
│   └── index.js          # Compiled server
├── package.json
└── tsconfig.json
```

## 🔄 Updating SmartContract VulnHunter

```bash
cd /home/ubuntu/SC-CLI
git pull
source venv/bin/activate
pip install -e .
```

## 🐛 Troubleshooting

### MCP Server Not Connected
```bash
# Check if build exists
ls ~/.opencode/mcp-servers/vulnhunter-mcp/build/

# Rebuild if needed
cd ~/.opencode/mcp-servers/vulnhunter-mcp
npm run build
```

### SmartContract VulnHunter Not Found
```bash
# Verify installation
ls /home/ubuntu/SC-CLI/src/vulnhunter/

# Check Python environment
/home/ubuntu/SC-CLI/venv/bin/python -c "import vulnhunter"
```

### Command Fails
```bash
# Test vulnhunter directly
/home/ubuntu/SC-CLI/venv/bin/python /home/ubuntu/SC-CLI/src/vulnhunter/main.py status
```

## 📚 Additional Resources

- [SmartContract VulnHunter README](./README.md)
- [Usage Guide](./USAGE.md)
- [Walkthrough](./WALKTHROUGH.md)
- [Recon Playbook](./recon-playbook.md)

## 🎯 Benefits of OpenCode Integration

1. **Unified Interface**: Access 15+ scanners from OpenCode
2. **LLM Orchestration**: Automatic deep analysis with Kimi K2.5
3. **Workflow Automation**: One-command full audits
4. **Platform Reports**: Generate submission-ready reports
5. **PoC Generation**: Auto-generate proof-of-concept exploits
6. **Multi-Chain Support**: Solidity, Rust/Solana, Vyper, Cairo

---

**Status**: Integrated ✅  
**MCP Server**: `vulnhunter` connected  
**Total MCP Servers**: 15 connected
