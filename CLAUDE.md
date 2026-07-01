# cloudcomply — CLAUDE.md

Project context for Claude Code. Read this before making any changes.

## What This Is

A lightweight Go CLI/TUI tool for assessing AWS Organizations against NIST SP 800-53 / RMF controls. The primary audience is Cloud Security Engineers and GRC practitioners working toward ATO packages or continuous compliance monitoring.

Key design constraints:
- **Zero installation in AWS CloudShell** — ships as a single static Linux binary
- **Low profile** — no agents, no sidecars, no persistent install
- **Termux-compatible** — must work well in a mobile terminal with external keyboard
- **Demo-first** — a polished demo mode (fake but realistic data) is a first-class feature, not an afterthought

## Tech Stack

| Tool | Purpose |
|------|---------|
| Go 1.21+ | Primary language |
| Bubble Tea | Full-screen TUI (Elm architecture) |
| Bubbles | TUI components — table, spinner, etc. |
| Lip Gloss | Terminal styling |
| Cobra | CLI command structure *(planned — not yet wired)* |
| AWS SDK v2 | Live Security Hub + Organizations calls *(planned)* |

## Architecture

### Hybrid TUI / CLI model

The tool has two modes:
- **Interactive (default):** `cloudcomply` with no args launches the Bubble Tea dashboard
- **Headless (planned):** `cloudcomply report nist --format json` for scripting/CI

Do not collapse these into one. Keep TUI and non-interactive paths separate.

### View system

Views are defined as `type view int` constants. The main `model` struct holds a `currentView` field. Each view has its own `update*` and `*View` methods. This pattern should be followed when adding new views — do not embed all logic in a single Update/View function.

Current views:
- `viewDashboard` — org summary + compliance score + main menu
- `viewFindings` — NIST 800-53 findings table with control family and DoD SRG Impact Level filter tabs

### Data model

`Finding` is the core type. Its fields mirror real AWS Security Hub NIST findings intentionally — switching from fake to live data means replacing `demoFindings()` only, nothing else.

```go
type Finding struct {
    ControlID        string
    Title            string
    Family           string        // "AC", "AU", "CM", "IA", "SC", "SI"
    Status           FindingStatus // PASSED | FAILED
    Severity         Severity      // CRITICAL | HIGH | MEDIUM | LOW
    AccountsAffected int
    RMFStep          string        // "Assess" | "Monitor" | "Implement" | etc.
    MinImpactLevel   ImpactLevel   // lowest DoD Cloud Computing SRG Impact Level (IL2/IL4/IL5/IL6) requiring this control for a Mission Owner
}
```

### Demo mode

`demoFindings()` in `main.go` generates ~27 realistic findings across 6 control families. The compliance score is calculated from this data (currently ~41%, intentionally low for demo realism). When adding live AWS integration, introduce a `--demo` flag rather than removing the fake data path.

## Common Commands

```bash
# Run the TUI
go run main.go

# Build
go build -ldflags="-s -w" -o cloudcomply .

# Cross-compile static binary for CloudShell
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cloudcomply-linux-amd64 .

# Tidy dependencies
go mod tidy
```

## Coding Conventions

- Keep Bubble Tea `Model`, `Update`, and `View` concerns separated — business logic does not belong in `View()`
- `buildTable()` is a pure function: takes findings + filter, returns a new `table.Model`. Keep it that way.
- Styles are package-level `var` blocks using `lipgloss.NewStyle()`. Add new styles there, not inline.
- No hardcoded AWS credentials anywhere — ever.
- Error handling: explicit, not panic. If an AWS call fails, surface it in the TUI as a status message.
- No comments explaining *what* code does. Only add a comment when the *why* is non-obvious.

## What's Done

- [x] Bubble Tea dashboard with org summary + NIST compliance score (color-coded by threshold)
- [x] Findings browser with sortable table and left/right control family filter tabs
- [x] View switching (dashboard ↔ findings)
- [x] Realistic fake data generator (`demoFindings`)
- [x] `.gitignore` covering binaries, credentials, reports, and local Claude settings
- [x] README with CloudShell quick start, IAM policy, keybindings, and status table

## What's Next (Planned Order)

1. **Cobra CLI structure** — `cmd/` package, `cloudcomply` launches TUI, subcommands for headless mode
2. **Finding detail pane** — press Enter on a table row to open a viewport showing full control description + RMF mapping + remediation guidance
3. **Live Security Hub integration** — `internal/awsclient/` package, `GetFindings` with NIST standard filter + org scope, async tea.Cmd pattern
4. **Threat modeling wizard** — `huh` forms, STRIDE categories, Markdown output
5. **Report export** — `--format markdown|json|html`, output suitable for ATO evidence packages

## IAM Requirements (for live mode)

Run from a role in the Security Hub delegated admin account:

```
securityhub:GetFindings
securityhub:GetFindingStatistics
organizations:ListAccounts
organizations:ListOrganizationalUnitsForParent
organizations:DescribeOrganization
sts:GetCallerIdentity
sts:AssumeRole  (if using cross-account checks)
```

## Important Constraints

- **Static binary** — `CGO_ENABLED=0` is required for CloudShell. Do not introduce CGO dependencies.
- **No heavy frameworks** — keep dependencies minimal. One binary, fast startup.
- **Termux-friendly** — avoid mouse-dependent interactions; all navigation must work with keyboard only.
- **Report output is sensitive** — generated reports may contain real account IDs and finding details. The `reports/` and `output/` directories are gitignored. Do not log sensitive data to stdout in non-interactive mode.
- **No breaking the headless path** — any change to data structures must keep `--format json` output stable (once implemented).
