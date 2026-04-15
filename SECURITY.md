# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in secretsh, **do not open a public issue.**

Instead, please report it privately:

1. **Email:** Send details to the maintainer via GitHub's email settings (profile page).
2. **GitHub Security Advisory:** Use GitHub's [private vulnerability reporting](https://github.com/lthoangg/secretsh/security/advisories/new) feature.

Include the following in your report:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix release:** as soon as practical, targeting 30 days for critical issues

## Scope

The following are considered in-scope vulnerabilities:

- Secret value leakage through any output channel (stdout, stderr, logs)
- Vault encryption bypasses or key recovery attacks
- Tokenizer bypasses that allow shell injection
- Memory disclosure of secret values after zeroization
- File descriptor leakage exposing vault contents to child processes
- HMAC/GCM verification bypasses allowing vault tampering

The following are explicitly **out of scope** (see [docs/threat-model.md](docs/threat-model.md)):

- `/proc/<pid>/cmdline` inspection by same-UID processes
- Physical memory attacks (cold boot, DMA)
- Malicious child processes exfiltrating their own argv
- Side-channel attacks on cryptographic implementations

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Only the latest release receives security updates.
