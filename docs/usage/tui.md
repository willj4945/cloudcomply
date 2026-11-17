# Interactive dashboard (TUI)

Run `cloudcomply` with no subcommand to open the full-screen dashboard. It uses the terminal's alternate screen, so your scrollback is restored when you quit.

```bash
cloudcomply          # live AWS data
cloudcomply --demo   # built-in sample data
```

## Dashboard

The landing screen shows:

| Field | Source |
|---|---|
| Organization / Account | AWS Organization ID, or the account ID in single-account mode |
| Accounts in Org / Accounts Scanned | `organizations:ListAccounts` count, or `1` in single-account mode |
| NIST 800-53 | `PASSED` ÷ (`PASSED` + `FAILED` + `ERROR`) controls, colored green (≥ 85%), orange (70–84%) or red (< 70%). See [scoring](../concepts/scoring.md#5-score). |
| DoD SRG (IL5 Mission Owner) | The same score limited to controls whose minimum Impact Level is IL5 or lower |

### Main menu

| Item | Action |
|---|---|
| Run Full NIST Compliance Scan | Fetches findings again and refreshes the dashboard |
| Browse Findings by Control Family | Opens the findings browser |
| Generate Threat Model | *Coming soon* |
| View Best Practices Report | *Coming soon* |
| Quit | Exits |

If loading fails (missing credentials, AccessDenied, timeout), the dashboard shows the error in a red box. Press `q` to quit, fix the cause (see [Troubleshooting](../troubleshooting.md)), or rerun with `--demo`.

## Findings browser

A scrollable table with one row per NIST control:

| Column | Meaning |
|---|---|
| Control | NIST SP 800-53 Rev. 5 control ID, e.g. `AC-2`, `SC-28(1)` |
| Title | Control title (in live mode, Security Hub's security-control title, see [scoring](../concepts/scoring.md#titles)) |
| Status | `PASSED`, `FAILED`, `ERROR` (couldn't be evaluated) or `N/A` (`NOT_APPLICABLE`, shortened to fit the column) |
| Severity | Highest severity among failing findings for the control |
| Accounts | Number of distinct accounts with at least one failing finding |
| RMF Step | `Assess` for failing or errored controls, `Monitor` otherwise |
| Min IL | Lowest DoD SRG Impact Level that requires the control |

There are two independent filters. The tally above the table (passed, failed, and error / n/a counts when non-zero) updates as you change them:

- **Family**: `ALL`, `AC`, `AU`, `CM`, `IA`, `SC`, `SI`
- **Impact Level**: `ALL`, `IL2`, `IL4`, `IL5`, `IL6`. Choosing a level shows every control required *at or below* it, since levels stack.

## Keybindings

| Key | Dashboard | Findings browser |
|---|---|---|
| `↑` / `k` | Previous menu item | Previous row |
| `↓` / `j` | Next menu item | Next row |
| `←` / `h` | | Previous family filter |
| `→` / `l` | | Next family filter |
| `[` | | Previous Impact Level filter |
| `]` | | Next Impact Level filter |
| `Enter` | Select menu item | |
| `Esc` / `q` | Quit (`q`) | Back to dashboard |
| `Ctrl+C` | Quit | Quit |

Everything is keyboard-driven, so the TUI works over SSH, in tmux, and in Termux with an external keyboard.

## Terminal requirements

- 256-color support (any modern terminal; CloudShell works out of the box)
- At least 80 columns for the findings table, and 100+ is more comfortable
- A UTF-8 locale so the arrows and box-drawing characters render
