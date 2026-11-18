# cloudcomply

[![CI](https://github.com/willj4945/cloudcomply/actions/workflows/ci.yml/badge.svg)](https://github.com/willj4945/cloudcomply/actions/workflows/ci.yml)
[![Docs](https://github.com/willj4945/cloudcomply/actions/workflows/docs.yml/badge.svg)](https://willj4945.github.io/cloudcomply/)
[![Go Reference](https://pkg.go.dev/badge/github.com/willj4945/cloudcomply.svg)](https://pkg.go.dev/github.com/willj4945/cloudcomply)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Assess an AWS Organization against NIST SP 800-53 Rev. 5 from a single static binary.** It runs in AWS CloudShell with nothing to install.

cloudcomply aggregates the NIST 800-53 findings AWS Security Hub already evaluates into one result per control across every account, scores them, and lets you slice them by control family and DoD Cloud Computing SRG Impact Level. You can use the interactive terminal dashboard or the headless JSON report for CI and ATO evidence.

📖 **Documentation: <https://willj4945.github.io/cloudcomply/>**

---

## Highlights

- **Org-wide NIST 800-53 score**: one row per control (FAILED if any account fails it), with severity and number of accounts affected
- **Interactive dashboard**: keyboard-only TUI with family (AC, AU, CM, IA, SC, SI) and Impact Level (IL2/4/5/6) filters
- **Headless reports**: `report nist --format json` with a stable schema for `jq`, CI gates and evidence trails
- **Single-account fallback**: works in a standalone account while org-wide access is still pending
- **Demo mode**: `--demo` runs everything offline with realistic sample data
- **Small, read-only footprint**: one static binary with no CGO, no agents, no config files and no telemetry. It only calls `Get`, `List` and `Describe` APIs.
- **Verifiable releases**: cosign-signed checksums and a CycloneDX SBOM for every binary

## Quick start

Try it offline:

```bash
go install github.com/willj4945/cloudcomply@latest
cloudcomply --demo
```

Run it live in **AWS CloudShell** from your Security Hub delegated admin account:

```bash
VERSION=v0.1.0   # latest tag from https://github.com/willj4945/cloudcomply/releases
curl -fsSLO "https://github.com/willj4945/cloudcomply/releases/download/${VERSION}/cloudcomply_${VERSION#v}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/willj4945/cloudcomply/releases/download/${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
tar -xzf "cloudcomply_${VERSION#v}_linux_amd64.tar.gz" cloudcomply
./cloudcomply
```

Generate a report for scripts or CI:

```bash
cloudcomply report nist                                   # table
cloudcomply report nist --format json | jq '[.[] | select(.status=="FAILED")]'
```

For other platforms, signature verification and building from source, see **[Installation](https://willj4945.github.io/cloudcomply/getting-started/installation/)**.

## Requirements

- AWS Security Hub enabled, with the **NIST SP 800-53 Rev. 5** standard turned on ([prerequisites](https://willj4945.github.io/cloudcomply/aws/prerequisites/))
- Credentials from the standard AWS credential chain (CloudShell, SSO, profile, role or OIDC) and a region set
- A read-only IAM policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "securityhub:GetFindings", "Resource": "*" },
    { "Effect": "Allow", "Action": ["organizations:DescribeOrganization", "organizations:ListAccounts"], "Resource": "*" }
  ]
}
```

See [IAM permissions](https://willj4945.github.io/cloudcomply/aws/permissions/) for the reason behind each action and for the managed-policy alternative.

## Documentation

| | |
|---|---|
| [Installation](https://willj4945.github.io/cloudcomply/getting-started/installation/) | Release binaries, `go install`, source builds, shell completion |
| [Quick start](https://willj4945.github.io/cloudcomply/getting-started/quickstart/) | Demo mode, CloudShell, workstation setup |
| [Dashboard (TUI)](https://willj4945.github.io/cloudcomply/usage/tui/) | Screens, filters, keybindings |
| [Command reference](https://willj4945.github.io/cloudcomply/usage/cli/) | Commands, flags, exit codes, environment variables |
| [JSON schema](https://willj4945.github.io/cloudcomply/usage/json-schema/) | Output contract and `jq` recipes |
| [CI/CD and automation](https://willj4945.github.io/cloudcomply/usage/automation/) | GitHub Actions with OIDC, GitLab, compliance gates |
| [How scoring works](https://willj4945.github.io/cloudcomply/concepts/scoring/) | Aggregation rules and what the score does and doesn't mean |
| [Security model](https://willj4945.github.io/cloudcomply/security/) | Data handling, supply chain, verifying releases |
| [Troubleshooting](https://willj4945.github.io/cloudcomply/troubleshooting/) | Common errors and fixes |

## Keybindings

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j` | Move |
| `←`/`h`, `→`/`l` | Previous / next control family filter |
| `[`, `]` | Previous / next DoD SRG Impact Level filter |
| `Enter` | Select |
| `Esc` / `q` | Back (findings) / quit (dashboard) |
| `Ctrl+C` | Quit |

## Project status

cloudcomply is **pre-1.0**. These parts work today:

| Feature | Status |
|---------|--------|
| Dashboard + NIST 800-53 compliance score | ✅ |
| Findings browser with family and Impact Level filters | ✅ |
| Live Security Hub + Organizations integration | ✅ |
| Headless `report nist --format table\|json` | ✅ |
| Demo mode | ✅ |
| NIST → DoD SRG Impact Level crosswalk for live data | 🔲 Planned (live findings currently report `IL2`) |
| Finding detail pane, Markdown/HTML export | 🔲 Planned |
| Scheduled runs, S3 history and drift detection | 🔲 Planned |
| Native Bedrock / SageMaker AI workload checks | 🔲 Planned |

See the full [roadmap](https://willj4945.github.io/cloudcomply/project/roadmap/).

> **Note:** cloudcomply reports on Security Hub's *automated* checks. It's continuous-monitoring evidence that supports an assessment, not a substitute for one. See [what the score is not](https://willj4945.github.io/cloudcomply/concepts/scoring/#what-this-score-is-not).

## Contributing

Issues and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security vulnerability, follow [SECURITY.md](SECURITY.md) and **don't** open a public issue.

## License

[MIT](LICENSE)
