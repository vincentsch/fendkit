# Install Fendkit

Release binaries need no Go runtime. Install the latest release with Bash:

```bash
curl -fsSL https://raw.githubusercontent.com/vincentsch/fendkit/main/install.sh -o install.sh
bash install.sh
```

The installer checks SHA-256 before replacing an existing installation.
It downloads assets from GitHub Releases without calling the GitHub API.
Linux and macOS are supported, as is Windows with a compatible Bash.
The default directory is `~/.local/bin`. You can choose another directory or tag:

```bash
INSTALL_DIR="$HOME/bin" FENDKIT_VERSION=v0.1.0 bash install.sh
fendkit --version
fendkit demo --offline
```

The offline demo exits 11 because it has no vulnerability lookup evidence.
The installer prints an instruction when you need to add its directory to PATH.
It needs `curl` and either `sha256sum` or `shasum`. It never runs `sudo`.
`FENDKIT_RELEASES_URL` overrides the release base URL for testing or a mirror.
Latest downloads use `<url>/latest/download/<asset>`. A selected tag uses
`<url>/download/<tag>/<asset>`, including for `checksums.txt`.

## Native Windows

Download `fendkit-windows-amd64.exe` or `fendkit-windows-arm64.exe`
and `checksums.txt` from the same [release](https://github.com/vincentsch/fendkit/releases).
In PowerShell, compare the SHA-256 hash with that asset's line in `checksums.txt`:

```powershell
Get-FileHash .\fendkit-windows-amd64.exe -Algorithm SHA256
```

Only after the values match, rename the binary to `fendkit.exe` and put it
in a directory on PATH. Run `fendkit --version` to check the installation.

## Build from source

Use the Go version in `go.mod`. Run `make build` to create `bin/fendkit`,
or run `go install ./cmd/fendkit` to install into your Go bin directory.
An untagged source build reports `dev`. Once a tag is public, a versioned install
such as `go install github.com/vincentsch/fendkit/cmd/fendkit@v0.1.0`
uses its module version.

When Go is available and the public module is reachable, the latest tagged
version can also be installed with:

```bash
go install github.com/vincentsch/fendkit/cmd/fendkit@latest
```

If there is no public release yet, report that limitation; do not skip checksum
verification to install a binary. Source builds are available to contributors
with checkout access. Return to [the README](../README.md#install-and-try-the-example)
for the complete first run, or use [agent instructions](../AGENTS.md).
