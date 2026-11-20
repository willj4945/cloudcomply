# Prove it works in a sandbox org

This walkthrough shows that cloudcomply reports real AWS data correctly. You
stand up a near-$0 sandbox AWS Organization, plant misconfigurations you
know about, and check that cloudcomply reports them. Then you recount the
results independently from raw Security Hub data and confirm the two match.

It's written for evaluators, security reviewers and anyone deciding whether
to adopt cloudcomply. If you just want to look around, the
[Quick start](quickstart.md) demo mode needs no AWS account at all.

## What this demonstrates

| Claim | How you show it |
|---|---|
| It reads real AWS data, not canned output | Findings appear for misconfigurations *you* planted, in accounts *you* created ([Plant known failures](#plant-known-failures), [Run cloudcomply](#run-cloudcomply)) |
| Its numbers are correct | An independent recount from raw `aws securityhub get-findings` output, with no cloudcomply code involved, matches cloudcomply's JSON exactly ([Verify the numbers independently](#verify-the-numbers-independently)) |
| It tracks change | Fix one planted issue, re-run, and the affected control's account count drops ([Show it tracks change](#show-it-tracks-change)) |
| It's safe to run in a production org | Read-only IAM policy with three actions, no agents, nothing installed in the accounts ([Safety and failure behavior](#safety-and-failure-behavior)) |
| It fails cleanly | Missing credentials produce one actionable line and a non-zero exit, not a stack trace ([Safety and failure behavior](#safety-and-failure-behavior)) |

Budget about an hour of hands-on time, plus **up to 24 hours** of waiting
after enabling Security Hub for the first full set of findings.

## Cost: what's free and what isn't

| Service | Cost for this walkthrough |
|---|---|
| AWS Organizations, member accounts, IAM, STS, CloudShell | Free |
| Security Hub CSPM | Free for the first 30 days per account per region |
| AWS Config (Security Hub needs it to evaluate controls) | **Not free.** Billed per configuration item recorded and per rule evaluation. Cents to a few dollars a month in a near-empty org if you limit recording ([Turn on Security Hub CSPM and Config](#turn-on-security-hub-cspm-and-config)) |
| One S3 bucket, one unattached security group | Effectively $0 (empty bucket; security groups are free) |

!!! warning "Free-plan accounts can't use Organizations"
    New AWS accounts start on the free plan, and free-plan accounts can't
    create or join an Organization. Upgrade the management account to the
    paid plan. Remaining sign-up credits carry over, and they'll usually
    absorb the Config charges, so most people see a $0 bill.

!!! tip "Set a guardrail first"
    In **Billing → Budgets**, create a monthly cost budget of **$1** with an
    email alert at 100% of actual spend.

AWS pricing changes; check the current Security Hub CSPM and Config pricing
pages before you begin.

## Build the sandbox org

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
[Prerequisites](../aws/prerequisites.md)). From the management account:

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

!!! tip
    Skipping this step is itself a useful demo: cloudcomply fails with
    `fetching organization summary: … AccessDenied`, the exact message
    documented in [Troubleshooting](../troubleshooting.md).

## Turn on Security Hub CSPM and Config

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

## Plant known failures

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

## Run cloudcomply

In CloudShell, signed in to (or switched into) `sandbox-security`:

```bash
# Download the release binary, or upload one you built (see [Installation](installation.md))
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

## Verify the numbers independently

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

## Show it tracks change

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

## Safety and failure behavior

Worth showing to a security reviewer:

- **Permissions:** cloudcomply needs exactly `securityhub:GetFindings`,
  `organizations:DescribeOrganization` and `organizations:ListAccounts`
  ([IAM permissions](../aws/permissions.md)). Attach only that policy to a
  test role and re-run [Run cloudcomply](#run-cloudcomply) to prove nothing else is required.
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

## Package the evidence

Keep these from the run for an adopter-facing write-up:

- Screenshots: dashboard, findings browser on the `SC` family, and the
  Security Hub CSPM console page for the same control.
- `output/expected.txt`, `output/actual.txt` and the `MATCH` line from [Verify the numbers independently](#verify-the-numbers-independently).
- The before/after diff from [Show it tracks change](#show-it-tracks-change).
- The cloudcomply version (`./cloudcomply --version`) and the date.

!!! danger "Redact before sharing"
    Screenshots show your org ID and account IDs, and `raw-findings.json`
    contains account IDs, ARNs and resource names. Share the derived files
    (`expected.txt`, `actual.txt`, the JSON reports, which hold no account
    IDs) rather than the raw findings, and never commit `output/`.

## Tear down (stop the charges)

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

## No org? Single-account variant

If you can't create an Organization, run [Turn on Security Hub CSPM and Config](#turn-on-security-hub-cspm-and-config) through [Show it tracks change](#show-it-tracks-change) in one standalone account.
Enable Security Hub CSPM directly and skip the delegation steps. cloudcomply
detects that the account isn't in an org and switches to single-account mode
automatically (dashboard shows `Account:` and `Accounts Scanned: 1`). The
independent recount in [Verify the numbers independently](#verify-the-numbers-independently) works unchanged.
