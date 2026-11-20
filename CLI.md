# cloudcomply CLI reference

The CLI reference now lives on the documentation site, so it stays in sync with the code:

- **[Command reference](https://willj4945.github.io/cloudcomply/usage/cli/)**: commands, flags, exit codes, environment variables
- **[JSON output schema](https://willj4945.github.io/cloudcomply/usage/json-schema/)**: the stable `report nist --format json` contract
- **[Interactive dashboard](https://willj4945.github.io/cloudcomply/usage/tui/)**: screens and keybindings

Source: [`docs/usage/`](docs/usage/).

Quick reminder:

```text
cloudcomply [--demo]                              launch the interactive dashboard
cloudcomply report nist [--format table|json]     print a NIST 800-53 report to stdout
cloudcomply completion <shell>                    print a shell completion script
cloudcomply --version | --help
```
