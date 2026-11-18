# Security Policy

## Supported versions

cloudcomply is pre-1.0. Only the **latest release** gets security fixes.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Don't open a public GitHub issue for security vulnerabilities.**

Report privately through [GitHub Security Advisories](https://github.com/willj4945/cloudcomply/security/advisories/new). Please include:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept
- Affected version(s) (`cloudcomply --version`)
- Any suggested mitigation

**Redact real AWS account IDs, ARNs and finding data** from anything you send.

You can expect an acknowledgement within 72 hours. Confirmed vulnerabilities get a patched release and a published advisory, with credit to the reporter unless you'd prefer to stay anonymous.

### In scope

- Code execution, terminal escape injection or memory-safety issues triggered by data cloudcomply reads (for example crafted Security Hub findings)
- Credential or sensitive-data leakage through output, logs or errors
- Any path that makes cloudcomply mutate AWS resources
- Weaknesses in the release, signing or CI pipeline

### Out of scope

- Vulnerabilities in AWS services themselves (report them to [AWS](https://aws.amazon.com/security/vulnerability-reporting/))
- Findings that need an attacker who already controls the user's AWS credentials or local machine
- Accuracy of NIST/SRG mappings (please open a normal issue)

## Security design

- **Read-only AWS access:** calls only `securityhub:GetFindings`, `organizations:DescribeOrganization`, `organizations:ListAccounts` and `sts:GetCallerIdentity`
- **No credential handling:** credentials come only from the standard AWS SDK credential chain. Nothing is stored, cached or logged.
- **No telemetry:** no outbound network calls except to AWS APIs
- **Terminal-safe output:** control characters are stripped from Security Hub text before it's displayed
- **Static binary:** `CGO_ENABLED=0`, with no dynamic linking or plugins
- **Sensitive output:** reports reveal control weaknesses. Treat them as confidential, and don't commit them or publish them as public CI artifacts.

More detail: <https://willj4945.github.io/cloudcomply/security/>

## Verifying release binaries

`checksums.txt` is signed with [Sigstore cosign](https://www.sigstore.dev/) keyless signing, bound to this repository's release workflow:

```bash
VERSION=v0.1.0
cosign verify-blob \
  --certificate-identity "https://github.com/willj4945/cloudcomply/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt

sha256sum --check --ignore-missing checksums.txt
```

Always pin `--certificate-identity` as shown. A wildcard identity regexp accepts signatures from any GitHub workflow.
