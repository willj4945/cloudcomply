# CI/CD and automation

`report nist` is built for unattended use: it has no TTY requirement, prints only the report on stdout, prints errors on stderr, and exits non-zero on any error.

## Gate on failing controls

`report nist` exits `0` when controls fail (see [exit codes](cli.md#exit-codes)), so use `jq -e` to turn your policy into an exit code:

```bash
# Fail if any CRITICAL control is failing
cloudcomply report nist --format json \
  | jq -e '[.[] | select(.status=="FAILED" and .severity=="CRITICAL")] | length == 0'

# Fail if overall compliance drops below 80%
cloudcomply report nist --format json \
  | jq -e '((map(select(.status=="PASSED")) | length) * 100 / length) >= 80'
```

!!! tip "Don't pipe straight into the gate"
    In a plain `cmd | jq` pipeline, an AWS error makes `jq` see empty input. Write the report to a file first (with `set -euo pipefail`), so a credential failure fails the job for the right reason and the evidence file is kept.

## GitHub Actions (OIDC, no long-lived keys)

Create an IAM role in the Security Hub delegated admin account. Give it the [read-only policy](../aws/permissions.md) and a trust policy for GitHub's OIDC provider, scoped to your repository and branch.

```yaml
name: NIST posture

on:
  schedule:
    - cron: "17 6 * * 1-5"   # weekdays
  workflow_dispatch:

permissions:
  contents: read
  id-token: write            # for AWS OIDC

jobs:
  nist:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v5
        with:
          role-to-assume: arn:aws:iam::<SECURITY_HUB_ADMIN_ACCOUNT_ID>:role/cloudcomply-readonly
          aws-region: us-east-1

      - name: Install cloudcomply
        env:
          VERSION: v0.1.0
        run: |
          curl -fsSLO "https://github.com/willj4945/cloudcomply/releases/download/${VERSION}/cloudcomply_${VERSION#v}_linux_amd64.tar.gz"
          curl -fsSLO "https://github.com/willj4945/cloudcomply/releases/download/${VERSION}/checksums.txt"
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf "cloudcomply_${VERSION#v}_linux_amd64.tar.gz" cloudcomply

      - name: Report
        run: |
          set -euo pipefail
          ./cloudcomply report nist --format json > nist.json

      - name: Gate on critical failures
        run: jq -e '[.[] | select(.status=="FAILED" and .severity=="CRITICAL")] | length == 0' nist.json

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nist-report
          path: nist.json
          retention-days: 30
```

!!! danger "Public repositories"
    In a **public** repository, workflow artifacts can be downloaded by anyone with read access, which is everyone. Run posture reports from a **private** repository, or send the output to a protected location such as an encrypted S3 bucket instead of uploading it as an artifact.

Pin the version you've verified (`VERSION`), and consider also checking the cosign signature in the workflow (see [Verifying releases](../verifying-releases.md)).

## GitLab CI

```yaml
nist-posture:
  image: public.ecr.aws/aws-cli/aws-cli:latest
  id_tokens:
    AWS_OIDC_TOKEN:
      aud: sts.amazonaws.com
  variables:
    AWS_REGION: us-east-1
    AWS_ROLE_ARN: arn:aws:iam::<ACCOUNT_ID>:role/cloudcomply-readonly
    AWS_WEB_IDENTITY_TOKEN_FILE: /tmp/web-identity-token
  script:
    - echo "$AWS_OIDC_TOKEN" > "$AWS_WEB_IDENTITY_TOKEN_FILE"
    - ./cloudcomply report nist --format json > nist.json
  artifacts:
    paths: [nist.json]
    expire_in: 30 days
```

## Scheduled evidence collection

To build a dated evidence trail for continuous monitoring (RMF Step 6):

```bash
#!/usr/bin/env bash
set -euo pipefail
out="reports/$(date -u +%Y-%m-%d)"
mkdir -p "$out"
cloudcomply report nist --format json > "$out/nist.json"
cloudcomply report nist               > "$out/nist.txt"
sha256sum "$out"/* > "$out/SHA256SUMS"
```

Diff successive JSON files to see which controls changed state:

```bash
diff <(jq -r '.[] | "\(.control_id) \(.status)"' reports/2026-11-01/nist.json) \
     <(jq -r '.[] | "\(.control_id) \(.status)"' reports/2026-11-08/nist.json)
```

Native scheduled runs (Lambda + EventBridge) with S3 storage and drift detection are on the [roadmap](../project/roadmap.md).
