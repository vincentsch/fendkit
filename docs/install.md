# Install Fendkit

Release binaries need no Go runtime. Install the latest release with Bash:

```bash
curl -fsSL https://raw.githubusercontent.com/vincentsch/fendkit/main/install.sh -o install.sh
bash install.sh
export PATH="$HOME/.local/bin:$PATH"
```

The installer checks SHA-256 before replacing an existing installation.
It downloads assets from GitHub Releases without calling the GitHub API.
Linux and macOS are supported, as is Windows with a compatible Bash.
The default directory is `~/.local/bin`. You can choose another directory or tag:

```bash
INSTALL_DIR="$HOME/bin" FENDKIT_VERSION=v0.1.0 bash install.sh
export PATH="$HOME/bin:$PATH"
fendkit --version
fendkit demo --offline
```

The offline demo exits 11 because it has no vulnerability lookup evidence.
The installer prints an instruction when you need to add its directory to PATH.
It needs `curl` and either `sha256sum` or `shasum`. It never runs `sudo`.
`FENDKIT_RELEASES_URL` overrides the release base URL for testing or a mirror.
Latest downloads use `<url>/latest/download/<asset>`. A selected tag uses
`<url>/download/<tag>/<asset>`, including for `checksums.txt`.

## Run it on your product

From your product's root, use the ZIP or folder you ship. Replace
`../dist/plugin.zip` with your release path:

```bash
fendkit doctor
fendkit init --release ../dist/plugin.zip
```

A missing profile is normal before init. Init shows the inventory before asking
for your decisions. It saves them in `cra.yml` and writes drafts and reports. Unknown
answers stay visible for later review. Read `cra/README.md` for the document
index and open `cra/reports/status.html` for next actions.

From another directory, add `--dir /path/to/product` to each command.
Relative release paths resolve from that product directory, not your current
shell directory; absolute release paths also work.

For later checks, keep `product.release` in `cra.yml` current and run:

```bash
fendkit scan
fendkit docs
fendkit check
```

Run docs and check after scan exits 0 (complete) or 11 (incomplete).
For any other scan exit, stop and repair the operational error first.
Use `scan --release ../dist/plugin.zip` only to override the saved release.
Check exit 10 means a policy failure; 11 means missing, incomplete or stale
evidence without a higher-priority policy failure. Exit 0 does not mean the
drafts are reviewed. Review the drafts yourself; outputs give no legal advice.
See [status rules](status-items.md) and [network requests and limits](../README.md#privacy-and-limits).

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

If no public release is available, build from source with checkout access.
Keep checksum verification for binary downloads.
Return to [the README](../README.md#install-and-try-the-example)
for the complete first run, or use [agent instructions](../AGENTS.md).
