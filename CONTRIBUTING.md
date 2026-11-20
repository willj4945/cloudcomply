# Contributing to cloudcomply

Thanks for your interest! The full guide is on the docs site:
**<https://willj4945.github.io/cloudcomply/project/contributing/>** (source: [`docs/project/contributing.md`](docs/project/contributing.md)).

## TL;DR

```bash
go test -race ./...
gofmt -l .                                          # must print nothing
go mod tidy && git diff --exit-code go.mod go.sum
golangci-lint run
```

- No CGO, minimal dependencies, keyboard-only TUI.
- cloudcomply is **read-only** against AWS. Never add a mutating API call.
- Never commit credentials, real account IDs or generated reports.
- Don't rename or remove fields in `report nist --format json` output.
- Report security issues privately per [SECURITY.md](SECURITY.md), not as public issues.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE) and that you'll follow the [Code of Conduct](CODE_OF_CONDUCT.md).
