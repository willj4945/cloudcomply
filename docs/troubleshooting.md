# Troubleshooting

Start with `aws sts get-caller-identity` in the same shell. If the AWS CLI can't authenticate, cloudcomply can't either.

Every live error suggests `--demo`. If demo mode works, the problem is in your AWS setup, not the binary.

## Error reference

### `no valid AWS credentials found: … Missing Region`

No region is configured. Set one:

```bash
export AWS_REGION=us-east-1
```

CloudShell sets this for you. On workstations, add `region = …` to the profile in `~/.aws/config`.

### `no valid AWS credentials found: … no EC2 IMDS role found` / `failed to refresh cached credentials`

No credential source resolved, or an SSO session expired.

- SSO: `aws sso login --profile <profile>`
- Make sure `AWS_PROFILE` names a profile that exists
- In containers, check the task or instance role is attached

### `fetching Security Hub findings: … AccessDeniedException`

The principal lacks `securityhub:GetFindings`, or an SCP denies it. See [IAM permissions](aws/permissions.md).

### `fetching Security Hub findings: … InvalidAccessException … not subscribed to AWS Security Hub`

Security Hub isn't enabled in this account and region. Check you're in the right region (the aggregation region for org-wide data).

### `fetching organization summary: … AccessDeniedException`

The account is in an AWS Organization, but the principal can't call `organizations:ListAccounts` or `DescribeOrganization`. This is common when running from a **Security Hub** delegated admin that isn't an **Organizations** delegated admin. See [Prerequisites → Organizations access](aws/prerequisites.md#4-organizations-access-optional).

### Dashboard shows 0% and the findings table is empty

No NIST findings came back:

- The NIST SP 800-53 Rev. 5 standard isn't enabled. See [Prerequisites](aws/prerequisites.md#2-the-nist-sp-800-53-rev-5-standard-is-enabled).
- It was enabled less than about 24 hours ago, so findings are still being generated.
- You're querying a region without findings and without cross-region aggregation.

### Only some accounts or regions appear

cloudcomply sees what Security Hub in the queried account and region can see. Turn on Organizations integration (member accounts) and cross-region aggregation (regions), then run from the delegated admin in the home region.

### Timeouts

`context deadline exceeded` means the AWS calls took more than 30 seconds. This usually happens with very large finding volumes or a slow proxy.

- Run from the aggregation region (fewer hops) and from inside AWS (CloudShell or EC2) rather than over a VPN.
- Check proxy settings (`HTTPS_PROXY`, `AWS_CA_BUNDLE`).
- If you consistently need more time, please [open an issue](https://github.com/willj4945/cloudcomply/issues) with an approximate finding count. A configurable timeout is a reasonable addition.

### `unsupported format "…" (want: table, json)`

`--format` accepts only `table` or `json`.

## TUI display problems

| Symptom | Fix |
|---|---|
| Boxes and arrows render as `?` or garbage | Use a UTF-8 locale: `export LANG=en_US.UTF-8` |
| Colors missing | Use a 256-color terminal: `export TERM=xterm-256color` |
| Table columns truncated or wrapped | Widen the terminal to at least 100 columns, or use `report nist` |
| Keys don't respond in Termux | Use an external keyboard or Termux's extra-keys row for arrows and `Esc` |

## Still stuck?

Open an [issue](https://github.com/willj4945/cloudcomply/issues/new/choose) with the version (`cloudcomply --version`), OS/arch, how you're authenticating, and the error text. **Redact account IDs and ARNs** before posting.
