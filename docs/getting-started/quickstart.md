# Quick start

## 1. Try it offline with demo data

You don't need AWS credentials for this step.

```bash
cloudcomply --demo
```

The demo dataset is a fictional "Acme Federal Org" with 47 accounts and 27 findings across six control families (AC, AU, CM, IA, SC, SI). It scores about 41% compliant on purpose, so there's plenty to explore.

- Press `↓` then `Enter` to open **Browse Findings by Control Family**.
- Press `←` / `→` (or `h` / `l`) to filter by control family.
- Press `[` / `]` to filter by DoD SRG Impact Level.
- Press `q` / `Esc` to go back, and `q` on the dashboard to quit.

The headless report also works offline:

```bash
cloudcomply report nist --demo
cloudcomply report nist --demo --format json | jq '.[0]'
```

## 2. Run against a real account in AWS CloudShell

CloudShell already has credentials and a region configured, so it is the quickest live path.

1. Open CloudShell in the **Security Hub delegated administrator account**, in your **aggregation region** if you use cross-region aggregation. See [Prerequisites](../aws/prerequisites.md).
2. Install the binary (see [Installation](installation.md#linux-aws-cloudshell)).
3. Confirm your identity, then launch:

```bash
aws sts get-caller-identity
./cloudcomply
```

A spinner appears while cloudcomply pages through Security Hub. Large organizations can take a few seconds. When it finishes, the dashboard shows:

- **Organization**: your AWS Organization ID (`o-…`). Organizations has no display name, so this is the ID.
- **Accounts in Org**: from `organizations:ListAccounts`.
- **NIST 800-53**: percentage of controls with no failing findings.
- **DoD SRG (IL5 Mission Owner)**: the same score limited to controls in scope at IL5.

If the credentials aren't part of an AWS Organization, cloudcomply switches to **single-account mode** on its own and scores just that account.

## 3. Run it from a workstation

cloudcomply uses the standard AWS SDK credential chain, the same one as the AWS CLI. Anything that works for `aws sts get-caller-identity` works here:

```bash
export AWS_PROFILE=security-audit      # SSO or named profile
export AWS_REGION=us-gov-west-1        # region where Security Hub aggregates findings
aws sso login                          # if using IAM Identity Center
cloudcomply
```

!!! warning "A region is required"
    Outside CloudShell, set `AWS_REGION` (or `region` in your profile). If it's missing, cloudcomply exits with `Missing Region`.

## 4. Produce a report

```bash
cloudcomply report nist                       # human-readable table
cloudcomply report nist --format json > reports/nist-$(date +%F).json
```

!!! danger "Reports are sensitive"
    Live reports contain real account counts and your control failure posture, which is exactly what an attacker would want to know. Store them like any other assessment evidence. `reports/` and `output/` are gitignored in this repo for that reason.

## Next steps

- [Command reference](../usage/cli.md)
- [Gate a CI pipeline on failed controls](../usage/automation.md)
- [Understand how the score is calculated](../concepts/scoring.md)
