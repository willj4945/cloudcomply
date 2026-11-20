# Testing cloudcomply Against Real AWS

A repeatable plan for connecting cloudcomply to a real AWS environment and
smoke-testing each build before you ship it. Pairs with [README.md](README.md)
(install/build) and the [command reference](https://willj4945.github.io/cloudcomply/usage/cli/) (command reference).

Since [f355469](../../commit/f355469), live mode is the **default** —
`cloudcomply` and `cloudcomply report nist` both call Security Hub and
Organizations unless you pass `--demo`. This doc covers the live path.

---

## 1. What "connecting" actually means

There's no config file or connection string. `internal/awsclient.New()` calls
`config.LoadDefaultConfig(ctx)`, so cloudcomply picks up whatever credentials
are ambient in the shell it's run from — same resolution order as the AWS
CLI:

1. CloudShell's instance role (no setup — this is the primary target
   environment)
2. `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` env vars
3. `~/.aws/credentials` / `~/.aws/config` (SSO profiles, named profiles)

Before testing, confirm the identity cloudcomply will see:

```bash
aws sts get-caller-identity
```

If that fails, cloudcomply will fail the same way — fix it at the AWS CLI
level first.

---

## 2. One-time test environment setup

**A standalone AWS account (no Organization) now works** — cloudcomply
detects `AWSOrganizationsNotInUseException` from `DescribeOrganization` and
falls back to single-account mode automatically, scoring just that one
account instead of failing. This matters if org-wide access is stuck behind
approval: you can test and demo against whatever single account you already
have Security Hub access to, then get org-wide results for free the moment
broader access comes through — no flag, no rebuild.

That means there are two setups worth testing, not one:

- **Single-account mode**: any one AWS account with Security Hub enabled.
  Fastest to stand up, and the one to use while org access is pending.
- **Org mode**: a real AWS Organization, for when you want to exercise
  multi-account aggregation and pagination.

**Recommended minimal setup (org mode):**

1. An AWS Organization (management account + ideally 1-2 member accounts, so
   `AccountsAffected` and pagination have something real to show).
2. **Security Hub enabled** in whichever account you'll run cloudcomply
   from — ideally the delegated Security Hub admin account, since that's
   the one with org-wide visibility. Security Hub has a 30-day free trial,
   which is plenty for build-to-build testing.
3. **The NIST SP 800-53 Rev 5 standard subscribed** in Security Hub
   (Security Hub console → Standards → enable "NIST SP 800-53 Rev. 5"). This
   is the exact standard `internal/awsclient/findings.go` filters on
   (`standards/nist-800-53/v/5.0.0`) — without it, every fetch legitimately
   returns zero findings.
4. If you want multi-account results, turn on Security Hub's central
   cross-account aggregation from the delegated admin account. Without it,
   `GetNISTFindings` only sees findings local to whatever account/region the
   credentials point at.
5. Apply the IAM policy from [IAM permissions](docs/aws/permissions.md)
   to the role/user you'll test with.

You don't need to seed fake findings — misconfigured resources in a sandbox
org will generate real ones within a few hours of enabling Security Hub.

---

## 3. Build

```bash
go build -ldflags="-s -w" -o cloudcomply .
```

Or cross-compile the CloudShell target if that's what you're testing against:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cloudcomply-linux-amd64 .
```

---

## 4. Release smoke test checklist

Run this top-to-bottom before shipping a build. Sections A-B need no AWS
access; C onward need the test account(s)/org from step 2. Section D only
needs a single account — start there if org access isn't available yet.

### A. Unit tests (no AWS needed)

- [ ] `go test ./...` passes — covers control-ID parsing, aggregation,
      severity/status mapping in `internal/awsclient/findings_test.go`

### B. Demo mode regression (no AWS needed)

Confirms the `--demo` fallback still works, since it's what users reach for
when live mode fails.

- [ ] `./cloudcomply --demo` — dashboard loads instantly, 40% score, "Acme
      Federal Org" / 47 accounts
- [ ] `./cloudcomply report nist --demo --format table` and `--format json`
      both match the schema documented in the [command reference](https://willj4945.github.io/cloudcomply/usage/cli/)

### C. Credential/permission failure paths

These should all fail with a clear, actionable stderr message and a non-zero
exit — never a panic or a raw AWS SDK stack trace.

- [ ] No credentials at all (unset `AWS_PROFILE`, run outside CloudShell):
      error contains `no valid AWS credentials found` and `try --demo`
- [ ] Expired/invalid credentials: same message
- [ ] Role missing `securityhub:GetFindings`: error is prefixed
      `fetching Security Hub findings:`
- [ ] Role missing `organizations:ListAccounts`/`DescribeOrganization`:
      error is prefixed `fetching organization summary:`

### D. Happy path — single-account mode

Run against credentials for an account that is **not** part of any AWS
Organization (or use an org member account without org-level permissions).

- [ ] `./cloudcomply` — dashboard shows `Account:` (not `Organization:`),
      the numeric AWS account ID as the name, `Accounts Scanned: 1`, and the
      orange "Single-account mode" notice below the summary box
- [ ] `cloudcomply report nist --format table` / `--format json` both
      return findings scoped to that one account — no error, no org call
      surfaced
- [ ] Confirm no `describe organization` / `fetching organization summary`
      error appears anywhere — the fallback should be silent to the user

### E. Happy path — org mode

- [ ] `./cloudcomply` — spinner shows while loading, then dashboard
      populates with `Organization:` label, the real org ID (e.g.
      `o-abc123xyz`, not a friendly name — Organizations has no
      display-name concept), and real account count under `Accounts in Org:`
- [ ] Findings browser (`Enter` on "Browse Findings by Control Family`):
      family filter (`h`/`l`) and impact-level filter (`[`/`]`) both work
      against real data volumes
- [ ] `cloudcomply report nist --format table` and `--format json` both
      return non-empty, schema-correct output
- [ ] `cloudcomply report nist --format json | jq '[.[] | select(.status=="FAILED")]'`
      round-trips cleanly
- [ ] Spot-check that a Security Hub control listing several NIST 800-53
      requirements (most do) shows up under **each** of those controls, and
      that any `ERROR` / `N/A` counts in the findings browser correspond to
      `NOT_AVAILABLE` findings in the Security Hub console
- [ ] Spot-check one control's `AccountsAffected` count against the Security
      Hub console for the same control ID — confirms the aggregation logic
      in `findings.go` isn't over/under-counting

### F. Edge cases specific to the current implementation

- [ ] Security Hub enabled but NIST standard **not** subscribed: expect zero
      findings and a 0% score (not a crash) — `ComplianceScore` returns 0
      on an empty slice, but worth confirming the TUI renders that
      gracefully rather than showing a stale/blank screen
- [ ] Single-account **org** (management account, no members): `AccountCount`
      shows 1 with `IsOrgMode: true` — distinct from single-account *mode*
      (`IsOrgMode: false`) in section D; both should render sensibly
- [ ] Enough findings to force pagination (Security Hub pages at 100): both
      `GetFindingsPaginator` and `ListAccountsPaginator` should page fully —
      compare total finding count against the Security Hub console
- [ ] Simulate a slow/unreachable AWS call (e.g. block the endpoint or use
      a throttled network) and confirm the 30s `fetchTimeout` produces a
      clean timeout error rather than a hang, in both the TUI and
      `report nist`
- [ ] Credentials with `sts:GetCallerIdentity` denied *and* not in an org:
      confirm the single-account fallback's own error
      (`get caller identity:`) surfaces cleanly rather than masking the
      original `DescribeOrganization` failure

### G. Known rough edges (not bugs to chase, just don't be surprised)

- `MinImpactLevel` is hardcoded to `IL2` for **every** live finding
  (`findings.go` TODO — the real NIST→DoD SRG crosswalk isn't built yet).
  Impact-level filtering in the TUI will look correct structurally but isn't
  meaningful against live data until that lands.
- The dashboard's "Run Full NIST Compliance Scan" menu item re-runs the
  fetch (spinner, then refreshed results) — confirm it in both live and
  demo mode.

---

## 5. Keeping tests repeatable across builds

A live AWS org's actual security posture drifts on its own (someone opens a
port, a finding gets remediated), which makes build-to-build diffs noisy. To
tell "the tool changed" apart from "the environment changed":

- Keep one sandbox account with deliberately static, unremediated
  misconfigurations as a fixed baseline, separate from any account real
  engineers are actively fixing things in.
- Prefer diffing `report nist --format json` output between builds
  (`jq`-diffable) over eyeballing the TUI.
- Re-run section A/B (unit tests + demo mode) on every build regardless —
  they're free and catch regressions unrelated to AWS state.

---

## Quick reference

```bash
aws sts get-caller-identity                              # confirm identity first
go build -ldflags="-s -w" -o cloudcomply .
./cloudcomply --demo                                      # baseline, no AWS
./cloudcomply                                              # live TUI
./cloudcomply report nist --format table                  # live, human-readable
./cloudcomply report nist --format json | jq '.'           # live, machine-readable
go test ./...                                              # unit tests
```
