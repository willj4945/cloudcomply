# Verifying releases

Each GitHub release includes:

| Asset | Purpose |
|---|---|
| `cloudcomply_<ver>_<os>_<arch>.tar.gz` / `.zip` | The binary, plus `LICENSE` and `README.md` |
| `checksums.txt` | SHA-256 of every archive and SBOM |
| `checksums.txt.sig` | Cosign signature over `checksums.txt` |
| `checksums.txt.pem` | Short-lived Fulcio signing certificate, bound to the release workflow's GitHub OIDC identity |
| `*.sbom.json` | CycloneDX software bill of materials for each binary |

## 1. Verify the signature on `checksums.txt`

Requires [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v2 or later.

```bash
VERSION=v0.1.0
cosign verify-blob \
  --certificate-identity "https://github.com/willj4945/cloudcomply/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

`Verified OK` means `checksums.txt` was produced by **this repository's** release workflow, **for this tag**, and logged in the public Rekor transparency log.

!!! danger "Pin the identity"
    Don't verify with `--certificate-identity-regexp '.*'`. That accepts a signature from **any** GitHub Actions workflow in any repository, which proves nothing about where the file came from.

## 2. Verify the archive checksum

```bash
sha256sum --check --ignore-missing checksums.txt   # Linux
shasum -a 256 --check --ignore-missing checksums.txt   # macOS
```

## 3. (Optional) Scan the SBOM

```bash
grype sbom:cloudcomply_${VERSION#v}_linux_amd64.sbom.json
```
