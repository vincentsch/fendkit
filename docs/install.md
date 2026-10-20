# Install Conformline

Release binaries need no Go runtime. The first release is still being prepared.
After it is published, install the latest release with Bash:

```bash
curl -fsSL https://raw.githubusercontent.com/vincentsch/conformline/main/install.sh -o install.sh
bash install.sh
```

The installer checks SHA-256 before replacing an existing installation.
It downloads assets from GitHub Releases without calling the GitHub API.
Linux and macOS are supported, as is Windows with a compatible Bash.
The default directory is `~/.local/bin`. You can choose another directory or tag:

```bash
INSTALL_DIR="$HOME/bin" CONFORMLINE_VERSION=v0.1.0 bash install.sh
conformline --version
conformline demo --offline
```

The offline demo exits 11 because it has no vulnerability lookup evidence.
The installer prints an instruction when you need to add its directory to PATH.
It needs `curl` and either `sha256sum` or `shasum`. It never runs `sudo`.
`CONFORMLINE_RELEASES_URL` overrides the release base URL for testing or a mirror.
Latest downloads use `<url>/latest/download/<asset>`. A selected tag uses
`<url>/download/<tag>/<asset>`, including for `checksums.txt`.

## Native Windows

Download `conformline-windows-amd64.exe` or `conformline-windows-arm64.exe`
and `checksums.txt` from the same [release](https://github.com/vincentsch/conformline/releases).
In PowerShell, compare the SHA-256 hash with that asset's line in `checksums.txt`:

```powershell
Get-FileHash .\conformline-windows-amd64.exe -Algorithm SHA256
```

Only after the values match, rename the binary to `conformline.exe` and put it
in a directory on PATH. Run `conformline --version` to check the installation.

## Build from source

Use the Go version in `go.mod`. Run `make build` to create `bin/conformline`,
or run `go install ./cmd/conformline` to install into your Go bin directory.
An untagged source build reports `dev`. Once a tag is public, a versioned install
such as `go install github.com/vincentsch/conformline/cmd/conformline@v0.1.0`
uses its module version.
