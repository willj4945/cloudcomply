# Contributing

Contributions are welcome: bug reports, docs fixes, new control mappings and code.

## Development setup

```bash
git clone https://github.com/willj4945/cloudcomply.git
cd cloudcomply
go build ./...
go test ./...
go run . --demo
```

Requires Go 1.24 or later. CI builds with the latest Go release.

## Before opening a pull request

```bash
gofmt -l .                      # must print nothing
go vet ./...
go test -race ./...
go mod tidy && git diff --exit-code go.mod go.sum
golangci-lint run               # v2, config in .golangci.yml
```

CI also runs gosec, govulncheck and Gitleaks. A PR has to pass all of them before merge.

## Project layout

```text
main.go                   entrypoint; version ldflags
cmd/                      Cobra commands (no business logic)
internal/nist/            domain types, scoring, demo data (no AWS SDK)
internal/awsclient/       the only package that imports the AWS SDK
internal/report/          headless table/JSON renderers
internal/tui/             Bubble Tea dashboard (one update*/*View pair per view)
docs/                     this documentation site (MkDocs Material)
```

## Ground rules

- **No CGO.** The binary must build with `CGO_ENABLED=0`.
- **Minimal dependencies.** Discuss any new module in an issue first.
- **Read-only AWS.** Never add an API call that mutates AWS state. Any new call needs a matching update to [IAM permissions](../aws/permissions.md).
- **No credentials** in code, tests, fixtures or docs, ever. Use obviously fake account IDs (`111111111111`).
- **Keep the JSON contract stable.** Don't rename or remove `report nist --format json` fields. Adding fields is fine.
- **Keyboard-only TUI.** No mouse-dependent interactions.
- **Errors, not panics.** Surface AWS failures as TUI status messages or stderr errors.

## Working on the docs

```bash
pip install -r docs/requirements.txt
mkdocs serve          # http://127.0.0.1:8000, live reload
mkdocs build --strict # what CI runs
```

Docs are published to GitHub Pages automatically when changes merge to `main`.

## Testing against real AWS

See [`TESTING.md`](https://github.com/willj4945/cloudcomply/blob/main/TESTING.md) for the release smoke-test checklist (credential failure paths, single-account and org modes, pagination, timeouts).

## Releasing (maintainers)

```bash
git tag -s v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

The `Release` workflow runs GoReleaser, which builds every platform, generates SBOMs, signs `checksums.txt` with cosign and publishes the GitHub release.
