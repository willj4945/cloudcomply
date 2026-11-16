# Installation

cloudcomply ships as one statically linked binary with no runtime dependencies. Pick whichever method suits your environment.

| Method | Best for | Needs Go? |
|---|---|---|
| [Release binary](#release-binary) | CloudShell, jump hosts, CI runners | No |
| [`go install`](#go-install) | Developers with a Go toolchain | Yes (1.24+) |
| [Build from source](#build-from-source) | Contributors, audited internal builds | Yes (1.24+) |

## Release binary

Releases are published on the [GitHub Releases page](https://github.com/willj4945/cloudcomply/releases) for:

| OS | Architectures | Archive |
|---|---|---|
| Linux | `amd64`, `arm64` | `.tar.gz` |
| macOS | `amd64`, `arm64` | `.tar.gz` |
| Windows | `amd64` | `.zip` |

Archive names follow `cloudcomply_<version>_<os>_<arch>.tar.gz`, where `<version>` has no leading `v` (for example `cloudcomply_0.1.0_linux_amd64.tar.gz`).

### Linux / AWS CloudShell

```bash
VERSION=v0.1.0   # replace with the latest tag from the Releases page
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BASE=https://github.com/willj4945/cloudcomply/releases/download/${VERSION}

curl -fsSLO "${BASE}/cloudcomply_${VERSION#v}_linux_${ARCH}.tar.gz"
curl -fsSLO "${BASE}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt

tar -xzf "cloudcomply_${VERSION#v}_linux_${ARCH}.tar.gz" cloudcomply
./cloudcomply --version
```

!!! tip "Keeping it in CloudShell"
    CloudShell keeps `$HOME` (1 GB) between sessions in the same region. Move the binary to `~/bin` and it stays on your `PATH` next time:
    `mkdir -p ~/bin && mv cloudcomply ~/bin/`

### macOS

```bash
VERSION=v0.1.0
ARCH=$(uname -m | sed 's/x86_64/amd64/')
curl -fsSLO "https://github.com/willj4945/cloudcomply/releases/download/${VERSION}/cloudcomply_${VERSION#v}_darwin_${ARCH}.tar.gz"
tar -xzf "cloudcomply_${VERSION#v}_darwin_${ARCH}.tar.gz" cloudcomply
xattr -d com.apple.quarantine cloudcomply 2>/dev/null || true   # binary is not Apple-notarized
./cloudcomply --version
```

### Windows

Download `cloudcomply_<version>_windows_amd64.zip` from the Releases page, extract `cloudcomply.exe`, and run it from Windows Terminal. The TUI needs a terminal with ANSI support; legacy `cmd.exe` consoles may render poorly.

### Verify what you downloaded

Every release ships a `checksums.txt`, signed with [Sigstore cosign](https://www.sigstore.dev/) keyless signing, plus a CycloneDX SBOM for each binary. Verifying the signature proves the checksums came from this repository's release workflow. See [Verifying releases](../verifying-releases.md).

## go install

```bash
go install github.com/willj4945/cloudcomply@latest
```

This installs into `$(go env GOPATH)/bin`. Builds made with `go install` report `dev` for `--version` because release ldflags aren't applied.

## Build from source

```bash
git clone https://github.com/willj4945/cloudcomply.git
cd cloudcomply
go build -ldflags="-s -w" -o cloudcomply .
./cloudcomply --demo
```

### Cross-compile a static binary for CloudShell

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cloudcomply-linux-amd64 .
```

You can then upload it to CloudShell (**Actions → Upload file**) and `chmod +x` it.

`CGO_ENABLED=0` is required. Without it the binary links against the host's libc and may not run on CloudShell's Amazon Linux image.

## Shell completion

```bash
# bash
cloudcomply completion bash > ~/.local/share/bash-completion/completions/cloudcomply
# zsh
cloudcomply completion zsh > "${fpath[1]}/_cloudcomply"
# fish
cloudcomply completion fish > ~/.config/fish/completions/cloudcomply.fish
```

Run `cloudcomply completion <shell> --help` for shell-specific details.

## Uninstall

cloudcomply writes no config, cache or state files. To uninstall it, delete the binary.
