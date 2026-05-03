# Security Policy

## Supported Versions

We support the latest release. Security patches are applied to the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| latest  | ✅                 |
| older   | ❌                 |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report them via:

- **Email**: security@vincents.ai
- **GitHub Security Advisories**: Use [GitHub's private vulnerability reporting](https://github.com/vincents-ai/enrichment-engine/security/advisories/new) for this repository.

We aim to respond within **24 hours** and provide a detailed response within **72 hours**, consistent with EU Cyber Resilience Act (CRA) Article 10 timelines.

### What to Include

- Description of the vulnerability
- Affected component and version
- Steps to reproduce (if applicable)
- Potential impact
- Any suggested fixes or mitigations

## Security Update Policy

| Severity | Response Time | Patch Target |
|----------|--------------|-------------|
| Critical / Exploited | 24 hours | 72 hours |
| Critical | 72 hours | 7 days |
| High | 7 days | 14 days |
| Medium / Low | 14 days | 30 days |

## GRC Mapping Data Integrity

The enrichment engine maps CVEs to GRC controls across 74 providers and 67 frameworks. Data integrity is critical for compliance accuracy. Report any incorrect or outdated mappings through the channels above.

## Third-Party Dependencies

This project uses Go modules with `go.sum` for dependency integrity. We monitor for known vulnerabilities in dependencies and update promptly.
