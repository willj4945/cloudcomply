# Testing cloudcomply Against Real AWS

This document has two parts:

- **[Part 1 — Prove it works](#part-1--prove-it-works)**: for anyone
  evaluating cloudcomply. Stand up a near-$0 sandbox AWS Organization,
  plant misconfigurations you know about, and show that cloudcomply reports
  them — then independently recount the results from raw Security Hub data
  and show they match.
- **[Part 2 — Release smoke test](#part-2--release-smoke-test)**: the
  maintainer checklist run before shipping each build.

Pairs with [README.md](README.md) (install/build) and the
[command reference](https://willj4945.github.io/cloudcomply/usage/cli/).

---

# Part 1 — Prove it works

## 1.1 What this demonstrates

| Claim | How you show it |
|---|---|
| It reads real AWS data, not canned output | Findings appear for misconfigurations *you* planted, in accounts *you* created (1.5, 1.6) |
| Its numbers are correct | An independent recount from raw `aws securityhub get-findings` output, with no cloudcomply code involved, matches cloudcomply's JSON exactly (1.7) |
| It tracks change | Fix one planted issue, re-run, and the affected control's account count drops (1.8) |
| It's safe to run in a production org | Read-only IAM policy with three actions, no agents, nothing installed in the accounts (1.9) |
| It fails cleanly | Missing credentials produce one actionable line and a non-zero exit, not a stack trace (1.9) |

Budget about an hour of hands-on time, plus **up to 24 hours** of waiting
after enabling Security Hub for the first full set of findings.

## 1.2 Cost: what's free and what isn't

| Service | Cost for this walkthrough |
|---|---|
| AWS Organizations, member accounts, IAM, STS, CloudShell | Free |
| Security Hub CSPM | Free for the first 30 days per account per region |
| AWS Config (Security Hub needs it to evaluate controls) | **Not free.** Billed per configuration item recorded and per rule evaluation. Cents to a few dollars a month in a near-empty org if you limit recording (1.4) |
| One S3 bucket, one unattached security group | Effectively $0 (empty bucket; security groups are free) |

Two things to know before you start:

- **New AWS accounts start on the free plan, and free-plan accounts can't
  create or join an Organization.** Upgrade the management account to the
  paid plan. Remaining sign-up credits carry over, and they'll usually
  absorb the Config charges, so most people see a $0 bill.
- **Set a guardrail first.** In Billing → Budgets, create a monthly
  cost budget of **$1** with an email alert at 100% of actual spend.

AWS pricing changes; check the current Security Hub CSPM and Config pricing
pages before you begin.

## 1.3 Build the sandbox org

Pick **one region** and use it for everything (examples use `us-east-1`).
Run CLI commands from CloudShell in the management account unless stated
otherwise.

```bash
export AWS_REGION=us-east-1

# 1. Create the organization (all features)
aws organizations create-organization --feature-set ALL

# 2. Create two member accounts. Each needs a unique email; plus-addressing
#    (you+security@example.com) works with most providers.
aws organizations create-account --email you+security@example.com --account-name sandbox-security
aws organizations create-account --email you+workload@example.com --account-name sandbox-workload

# 3. Wait for both to report SUCCEEDED, then note the account IDs
aws organizations list-create-account-status --states SUCCEEDED \
  --query 'CreateAccountStatuses[].[AccountName,AccountId]' --output table
```

You'll end up with three accounts:

| Account | Role in the demo |
|---|---|
| Management | Owns the org. Nothing else runs here. |
| `sandbox-security` | Security Hub delegated admin. **cloudcomply runs here.** |
| `sandbox-workload` | Holds the planted misconfigurations. |

To act inside a member account, use **Switch role** in the console (or a CLI
profile) with the `OrganizationAccountAccessRole` that Organizations created
in each new account:

```ini
# ~/.aws/config
[profile sandbox-security]
role_arn          = arn:aws:iam::<SECURITY_ACCOUNT_ID>:role/OrganizationAccountAccessRole
credential_source = EcsContainer
region            = us-east-1

[profile sandbox-workload]
role_arn          = arn:aws:iam::<WORKLOAD_ACCOUNT_ID>:role/OrganizationAccountAccessRole
credential_source = EcsContainer
region            = us-east-1
```

`credential_source = EcsContainer` is for CloudShell in the management
account. From a laptop, replace it with `source_profile = <your management
account profile>`.

### Let the security account read the org

cloudcomply calls `organizations:ListAccounts`, which only works from the
management account or an **Organizations** delegated admin. Being the
Security Hub delegated admin isn't enough (see
[Prerequisites](docs/aws/prerequisites.md)). From the management account:

```bash
cat > org-delegation.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "CloudcomplyReadOrg",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<SECURITY_ACCOUNT_ID>:root" },
    "Action": ["organizations:DescribeOrganization", "organizations:ListAccounts"],
    "Resource": "*"
  }]
}
EOF
aws organizations put-resource-policy --content file://org-delegation.json
```

> Skipping this step is itself a useful demo: cloudcomply fails with
> `fetching organization summary: … AccessDenied`, the exact message
> documented in [Troubleshooting](docs/troubleshooting.md).

## 1.4 Turn on Security Hub CSPM and Config

1. **Config, in every account (management, security, workload).** In the
   AWS Config console, choose **Get started** → record **specific resource
   types** rather than all of them. To cover the planted issues below,
   record `AWS::S3::Bucket` and `AWS::EC2::SecurityGroup`. Recording fewer
   types is the main cost control.
2. **Delegate Security Hub admin.** In the management account, open
   Security Hub CSPM → **Settings → General → Delegated administrator** and
   enter the `sandbox-security` account ID.
3. **Configure the org centrally.** In `sandbox-security`, open Security
   Hub CSPM → **Configuration** → start **central configuration**. Create a
   configuration policy that:
   - enables Security Hub CSPM,
   - enables **only** the **NIST SP 800-53 Rev. 5** standard (turn off
     AWS Foundational Security Best Practices and anything else that's on by
     default, since every extra standard multiplies check costs),
   - is applied to the **organization root**, so every account gets it.
4. **Confirm** each account shows NIST SP 800-53 Rev. 5 as enabled in
   Security Hub CSPM → Standards. This is the exact standard cloudcomply
   filters on (`standards/nist-800-53/v/5.0.0`); without it every run
   legitimately returns zero findings.

Findings from member accounts flow to the delegated admin automatically in
the same region. Change-triggered controls report within minutes to hours;
periodic controls can take up to 24 hours.

## 1.5 Plant known failures

Knowing the expected answer in advance is what makes the demo convincing.
Each planted issue below is harmless: nothing is reachable from the
internet and nothing holds data.

| # | What you do | Security Hub control that should fail |
|---|---|---|
| 1 | Nothing. New accounts' default VPC security group allows traffic between its members out of the box | `EC2.2` — default security group should not allow inbound/outbound traffic |
| 2 | Create an S3 bucket with no bucket policy (so HTTP isn't denied) | `S3.5` — buckets should require SSL |
| 3 | Create a security group allowing port 22 from `0.0.0.0/0`, attached to nothing | `EC2.13` — no ingress from 0.0.0.0/0 to port 22 |
| 4 | Nothing. No CloudTrail trail exists yet | `CloudTrail.1` — multi-region trail with management events |
| 5 | Nothing. Root user of a fresh member account has no hardware MFA | `IAM.6` — hardware MFA for the root user |

Items 1, 4 and 5 fail in every new account without you doing anything.
Items 2 and 3, in `sandbox-workload`:

```bash
export AWS_PROFILE=sandbox-workload
ACCT=$(aws sts get-caller-identity --query Account --output text)

# Planted issue 2: bucket without a TLS-only policy
BUCKET="cloudcomply-demo-${ACCT}"
aws s3 mb "s3://${BUCKET}"

# Planted issue 3: SSH open to the world, attached to nothing
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
  --query 'Vpcs[0].VpcId' --output text)
SG=$(aws ec2 create-security-group --vpc-id "$VPC" \
  --group-name cloudcomply-demo-open-ssh \
  --description "cloudcomply demo - intentionally noncompliant, attach to nothing" \
  --query GroupId --output text)
aws ec2 authorize-security-group-ingress --group-id "$SG" \
  --protocol tcp --port 22 --cidr 0.0.0.0/0

echo "BUCKET=$BUCKET SG=$SG"   # keep these for remediation and teardown
```

Each Security Hub control maps to several NIST 800-53 controls. Open any
failing control in the Security Hub CSPM console and look at **Related
requirements** to see which NIST IDs to expect in cloudcomply. `S3.5`, for
example, includes `SC-8` (transmission confidentiality and integrity), and
the security group controls include `SC-7` (boundary protection).

## 1.6 Run cloudcomply

In CloudShell, signed in to (or switched into) `sandbox-security`:

```bash
# Download the release binary, or upload one you built (see Part 2)
chmod +x cloudcomply
aws sts get-caller-identity   # confirm you're in sandbox-security

./cloudcomply                 # interactive dashboard
```

What to point out:

- **Dashboard:** `Organization:` shows your real org ID (`o-…`) and
  `Accounts in Org: 3`. The compliance score is real and low, because you
  just planted failures.
- **Findings browser** (`Enter` on *Browse Findings by Control Family*):
  `SC` shows `SC-7` and `SC-8` as `FAILED`. Use `h`/`l` to switch families.
- **Headless mode** for CI and evidence:

```bash
mkdir -p output
./cloudcomply report nist --format table
./cloudcomply report nist --format json > output/before.json
jq '[.[] | select(.status == "FAILED")] | length' output/before.json
```

## 1.7 Verify the numbers independently

This is the key step. It recomputes cloudcomply's per-control results from
raw Security Hub data using only the AWS CLI and `jq`, then diffs the two.
If cloudcomply over- or under-counted anything, the diff shows it.

```bash
# Raw findings: same filters cloudcomply uses (NIST standard, active records).
# The AWS CLI pages through every result automatically.
aws securityhub get-findings --filters '{
  "ComplianceAssociatedStandardsId": [{"Value": "standards/nist-800-53/v/5.0.0", "Comparison": "EQUALS"}],
  "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
}' --output json > output/raw-findings.json

# Expected: for each NIST control, the number of distinct accounts with at
# least one FAILED finding mapped to it
jq -r '[.Findings[] | select(.Compliance.Status == "FAILED") | .AwsAccountId as $acct
  | (.Compliance.RelatedRequirements // [])[] | select(startswith("NIST.800-53.r5 "))
  | {control: (ltrimstr("NIST.800-53.r5 ") | gsub("^\\s+|\\s+$"; "")), acct: $acct}]
  | group_by(.control)[] | "\(.[0].control) \(map(.acct) | unique | length)"' \
  output/raw-findings.json | sort > output/expected.txt

# Actual: what cloudcomply reports
./cloudcomply report nist --format json \
  | jq -r '.[] | select(.status == "FAILED") | "\(.control_id) \(.accounts_affected)"' \
  | sort > output/actual.txt

diff output/expected.txt output/actual.txt && echo "MATCH: $(wc -l < output/actual.txt) failing controls agree"
```

Run the two fetches back to back. Security Hub updates continuously, so
minutes apart they can legitimately differ. If they disagree, re-run both.

For a spot check that doesn't depend on `jq`, open one control in the
Security Hub CSPM console (e.g. `S3.5` → **Checks**) and compare the
failing accounts against the matching NIST control's `accounts_affected`.

## 1.8 Show it tracks change

Fix planted issue 2 in `sandbox-workload` by requiring TLS on the bucket:

```bash
export AWS_PROFILE=sandbox-workload
cat > tls-only.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::${BUCKET}", "arn:aws:s3:::${BUCKET}/*"],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}
EOF
aws s3api put-bucket-policy --bucket "$BUCKET" --policy file://tls-only.json
```

`S3.5` is change-triggered, so Security Hub re-evaluates it shortly after.
Wait until the console shows `S3.5` as `PASSED` for that bucket, then, back
in `sandbox-security`:

```bash
./cloudcomply report nist --format json > output/after.json

# Per-control account counts that changed between runs
jq -r --slurpfile before output/before.json '
  ($before[0] | map({(.control_id): .accounts_affected}) | add) as $b
  | .[] | select(.accounts_affected != ($b[.control_id] // 0))
  | "\(.control_id): \($b[.control_id] // 0) -> \(.accounts_affected)"' output/after.json
```

The NIST controls mapped to `S3.5` (such as `SC-8`) should drop by one
account. They only flip to `PASSED` if no other check fails them anywhere in
the org.

## 1.9 Safety and failure behavior

Worth showing to a security reviewer:

- **Permissions:** cloudcomply needs exactly `securityhub:GetFindings`,
  `organizations:DescribeOrganization` and `organizations:ListAccounts`
  ([IAM permissions](docs/aws/permissions.md)). Attach only that policy to a
  test role and re-run 1.6 to prove nothing else is required.
- **Footprint:** nothing was deployed into any account. Nothing was
  installed apart from a single binary in CloudShell's home directory.
- **Clean failure:** with no credentials, the run stops with one line and
  exit code 1:

```bash
env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
    -u AWS_CONTAINER_CREDENTIALS_FULL_URI -u AWS_CONTAINER_AUTHORIZATION_TOKEN \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true \
  ./cloudcomply report nist; echo "exit=$?"
# no valid AWS credentials found: … (try --demo)
# exit=1
```

## 1.10 Package the evidence

Keep these from the run for an adopter-facing write-up:

- Screenshots: dashboard, findings browser on the `SC` family, and the
  Security Hub CSPM console page for the same control.
- `output/expected.txt`, `output/actual.txt` and the `MATCH` line from 1.7.
- The before/after diff from 1.8.
- The cloudcomply version (`./cloudcomply --version`) and the date.

**Redact before sharing.** Screenshots show your org ID and account IDs, and
`raw-findings.json` contains account IDs, ARNs and resource names. Share the
derived files (`expected.txt`, `actual.txt`, the JSON reports, which hold no
account IDs) rather than the raw findings. `output/` is gitignored for this
reason; don't commit it.

## 1.11 Tear down (stop the charges)

Security Hub CSPM and Config keep billing until you turn them off.

```bash
# Workload account: remove planted resources
export AWS_PROFILE=sandbox-workload
aws ec2 delete-security-group --group-id "$SG"
aws s3 rb "s3://${BUCKET}" --force
```

Then:

1. In `sandbox-security`, edit the central configuration policy to
   **disable** Security Hub CSPM for the organization, and wait until the
   member accounts show it disabled.
2. Stop and delete the Config recorder in **every** account:

   ```bash
   aws configservice describe-configuration-recorders --query 'ConfigurationRecorders[].name'
   aws configservice stop-configuration-recorder --configuration-recorder-name <name>
   aws configservice delete-configuration-recorder --configuration-recorder-name <name>
   ```

3. Optional: close the member accounts (**Organizations → AWS accounts →
   Close**). Closed accounts stay suspended for 90 days before AWS deletes
   them.
4. Check **Billing → Bills** a few days later to confirm nothing is still
   accruing.

### No org? Single-account variant

If you can't create an Organization, run 1.4–1.8 in one standalone account.
Enable Security Hub CSPM directly and skip the delegation steps. cloudcomply
detects that the account isn't in an org and switches to single-account mode
automatically (dashboard shows `Account:` and `Accounts Scanned: 1`). The
independent recount in 1.7 works unchanged.

---

# Part 2 — Release smoke test

A repeatable checklist for smoke-testing each build against real AWS before
shipping it. Since [f355469](../../commit/f355469), live mode is the
**default**: `cloudcomply` and `cloudcomply report nist` both call Security
Hub and Organizations unless you pass `--demo`.

## 2.1 What "connecting" actually means

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

## 2.2 One-time test environment setup

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

## 2.3 Build

```bash
go build -ldflags="-s -w" -o cloudcomply .
```

Or cross-compile the CloudShell target if that's what you're testing against:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cloudcomply-linux-amd64 .
```

---

## 2.4 Release smoke test checklist

Run this top-to-bottom before shipping a build. Sections A-B need no AWS
access; C onward need the test account(s)/org from 2.2 (or the Part 1 sandbox). Section D only
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

## 2.5 Keeping tests repeatable across builds

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

## 2.6 Quick reference

```bash
aws sts get-caller-identity                              # confirm identity first
go build -ldflags="-s -w" -o cloudcomply .
./cloudcomply --demo                                      # baseline, no AWS
./cloudcomply                                              # live TUI
./cloudcomply report nist --format table                  # live, human-readable
./cloudcomply report nist --format json | jq '.'           # live, machine-readable
go test ./...                                              # unit tests
```
