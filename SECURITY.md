# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within SmartContract VulnHunter, please send an email to security@vulnhunter.dev. All security vulnerabilities will be promptly addressed.

Please include the following details in your report:
- Type of vulnerability
- Full paths of source file(s) related to the manifestation of the vulnerability
- Location of affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Impact of the vulnerability
- Suggested fixes (if any)

## Security Considerations

### API Keys and Secrets

SmartContract VulnHunter requires various API keys to function:
- LLM API keys (Kimi/OpenAI-compatible)
- GitHub/GitLab tokens (for private repo cloning)

**Important:** Never commit these keys to version control. Use environment variables:

```bash
export VULNHUNTER_LLM__API_KEY="your-api-key"
```

### Running in Production

When running SmartContract VulnHunter in production:

1. **Use environment variables** for all secrets
2. **Regular dependency updates** - Run `pip-audit` regularly
3. **Isolate scanning** - Run in containers or VMs for untrusted code
4. **Review generated PoCs** - Always review before deployment
5. **Rate limiting** - Implement for LLM calls to control costs

### Security Features

- No private key storage
- Read-only blockchain access
- Safe subprocess execution (no shell=True)
- Timeout controls on all external processes
- Input validation on all CLI arguments

## Security Updates

Security updates will be released as patch versions (e.g., 0.1.1, 0.1.2).

Subscribe to security advisories by watching this repository on GitHub.
