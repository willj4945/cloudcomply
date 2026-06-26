# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | ✅ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](../../security/advisories/new).

Include:
- Description of the issue and potential impact
- Steps to reproduce
- Affected versions
- Any suggested mitigations

You can expect a response within 72 hours. If a vulnerability is confirmed, a patched release will be issued as quickly as possible.

## Security Design Notes

This tool is designed with the following security properties:

- **Read-only AWS access** — the tool never writes to, modifies, or deletes AWS resources
- **No credential storage** — AWS credentials are sourced exclusively from the standard SDK credential chain (environment variables, `~/.aws/credentials`, instance profiles, CloudShell session)
- **No telemetry** — the tool makes no outbound network calls except to AWS APIs
- **Static binary** — no dynamic linking, no runtime dependency resolution
- **Report output is sensitive** — generated reports contain account IDs and finding details; treat them as confidential and do not commit them to version control

## Verifying Release Binaries

All release binaries are signed with [Sigstore cosign](https://sigstore.dev) using keyless signing tied to the GitHub Actions OIDC identity.

Verify a downloaded binary:

```bash
# Verify the checksums file signature
cosign verify-blob \
  --certificate-identity "https://github.com/willj4945/cloudcomply/.github/workflows/release.yml@refs/tags/<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt

# Then verify the binary checksum
sha256sum --check checksums.txt --ignore-missing
```
