# Security Policy

## Scope

This project is a **local, offline security research and educational tool**. It is not a hosted service. The attack surface covered by this policy is the application's own code — not the LLMs or cloud APIs it connects to.

## Supported Versions

| Version | Supported |
|:--------|:----------|
| `main` branch | Yes |
| Older tags | No — please update to `main` |

## Responsible Disclosure

If you discover a security vulnerability in this codebase (e.g., command injection, path traversal, unsafe deserialization, credential leakage), please **do not open a public GitHub issue**.

Instead, report it privately via one of these channels:

1. **GitHub Private Vulnerability Reporting** (preferred): Use the "Report a vulnerability" button under the Security tab of this repository.
2. **Email:** security@your-org.example.com *(replace with your actual contact)*

Please include:
- A description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept.
- The version/commit hash where you observed the issue.

We aim to acknowledge reports within **72 hours** and provide a remediation timeline within **7 days**.

## Ethical Use

This tool is designed for authorized security testing, AI safety research, and education. By using it you agree to:

- Only run red-team attacks against systems and LLMs you are **authorized** to test.
- Not use this tool to generate or distribute harmful content.
- Comply with the terms of service of any cloud APIs used (e.g., Palo Alto Prisma AIRS).

Misuse of this tool against systems without authorization may violate applicable law.
