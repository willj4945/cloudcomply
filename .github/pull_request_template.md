## Summary

<!-- What does this change and why? Link related issues. -->

## Checklist

- [ ] `go test -race ./...` and `golangci-lint run` pass
- [ ] Docs under `docs/` updated for any user-visible change (commands, flags, output, IAM)
- [ ] No new AWS API calls, or each new call is read-only and added to `docs/aws/permissions.md`
- [ ] `report nist --format json` fields unchanged (additions only)
- [ ] No credentials, real account IDs or generated reports in the diff
