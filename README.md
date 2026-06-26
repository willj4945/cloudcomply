# cloudcomply

A lightweight, interactive CLI/TUI for assessing AWS Organizations against NIST SP 800-53 controls. Designed to run directly in AWS CloudShell with zero installation — drop in a single static binary and go.

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## Features

- **Org-wide visibility** — enumerate all accounts and OUs across an AWS Organization
- **NIST 800-53 compliance scoring** — aggregated findings from AWS Security Hub mapped to control families (AC, AU, CM, IA, SC, SI, and more)
- **Interactive findings browser** — filter by control family, see pass/fail status, severity, and accounts affected
- **RMF alignment** — findings tagged to the relevant RMF step (Categorize, Select, Implement, Assess, Authorize, Monitor)
- **Threat modeling** — guided wizard to generate STRIDE-based threat models for AWS workloads *(coming soon)*
- **Best practices report** — custom checks beyond Security Hub standards *(coming soon)*
- **Export-ready** — Markdown and JSON output suitable for ATO evidence packages *(coming soon)*
- **Demo mode** — realistic fake data for offline use, demos, and portfolio showcases

---

## Quick Start

### Run in AWS CloudShell (recommended)

Download the latest static Linux binary from [Releases](../../releases) and run it directly — no Go installation needed:

```bash
curl -LO https://github.com/yourname/cloudcomply/releases/latest/download/cloudcomply-linux-amd64
chmod +x cloudcomply-linux-amd64
./cloudcomply-linux-amd64
```

### Build from source

Requires Go 1.21+.

```bash
git clone https://github.com/yourname/cloudcomply.git
cd cloudcomply
go build -ldflags="-s -w" -o cloudcomply .
./cloudcomply
```

### Cross-compile a static binary for CloudShell

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cloudcomply-linux-amd64 .
```

---

## Navigation

| Key | Action |
|-----|--------|
| `↑` / `k` | Move up |
| `↓` / `j` | Move down |
| `←` / `h` | Previous control family filter |
| `→` / `l` | Next control family filter |
| `Enter` | Select / open |
| `Esc` / `q` | Back / quit |
| `Ctrl+C` | Force quit |

---

## AWS Permissions

The tool requires read-only access. Run from a role in your Security Hub delegated admin account with at minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:GetFindingStatistics",
        "securityhub:ListFindingAggregators",
        "organizations:ListAccounts",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:DescribeOrganization",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

For cross-account checks: add `sts:AssumeRole` and a trust policy in member accounts.

---

## Project Status

| Feature | Status |
|---------|--------|
| Dashboard + NIST compliance score | ✅ Done |
| Findings browser (with family filter) | ✅ Done |
| Demo mode (realistic fake data) | ✅ Done |
| Cobra CLI command structure | 🔲 Planned |
| Live Security Hub integration | 🔲 Planned |
| Threat modeling wizard | 🔲 Planned |
| Best practices custom checks | 🔲 Planned |
| Markdown / JSON report export | 🔲 Planned |

---

## Tech Stack

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) — TUI framework
- [Bubbles](https://github.com/charmbracelet/bubbles) — table, spinner, and other TUI components
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) — terminal styling
- [AWS SDK for Go v2](https://github.com/aws/aws-sdk-go-v2) — AWS API client *(planned)*
- [Cobra](https://github.com/spf13/cobra) — CLI command structure *(planned)*

---

## NIST / RMF Mapping

Findings are mapped to NIST SP 800-53 Rev. 5 control families and tagged to the relevant RMF step, making them directly usable as evidence in an ATO package.

| Control Family | Coverage |
|----------------|----------|
| AC — Access Control | ✅ |
| AU — Audit and Accountability | ✅ |
| CM — Configuration Management | ✅ |
| IA — Identification and Authentication | ✅ |
| SC — System and Communications Protection | ✅ |
| SI — System and Information Integrity | ✅ |
| Additional families | Planned |

---

## License

MIT
