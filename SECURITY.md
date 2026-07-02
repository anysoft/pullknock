# Security Policy

## Supported Versions

PullKnock is currently in early development. Security fixes are provided for the latest released version only.

| Version | Supported |
| --- | --- |
| Latest | ✅ |
| Older versions | ❌ |

## Reporting a Vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Preferred reporting methods:

1. Use GitHub private vulnerability reporting, if enabled for this repository.
2. Or contact the maintainer privately.

When reporting a vulnerability, please include:

- A clear description of the issue.
- Affected version or commit.
- Steps to reproduce.
- Potential impact.
- Any suggested mitigation, if available.

## Scope

Security-sensitive areas include:

- SSHSIG signing and verification.
- Canonical JSON parsing.
- Envelope parsing and age decryption.
- Nonce replay protection.
- User, key, group, and grant authorization.
- firewalld and nftables command construction.
- Publisher service authentication.
- Web admin write/reload operations.
- GitHub Actions release and publishing workflows.

## Handling Process

After receiving a report, maintainers will try to:

1. Confirm receipt.
2. Reproduce and assess severity.
3. Prepare a fix privately.
4. Publish a release and advisory if needed.
5. Credit the reporter unless anonymity is requested.

## Security Principles

PullKnock treats publisher URLs, object storage, WebDAV, FTP, IPFS, and other message boards as untrusted. Authorization must rely on signed payloads, nonce replay protection, local agent policy, and short-lived firewall timeout rules.
