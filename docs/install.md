# Install Fendkit

Fendkit is a free tool for small software makers preparing for the EU Cyber
Resilience Act, a law about product security. You run it by typing commands in
your computer's terminal. It checks software you include from other developers
for known security problems. It also writes draft documents for you to review.

Install the latest release with Bash. You do not need Go:

```bash
if (
  fendkit_installer_dir="$(mktemp -d)" || exit
  trap 'rm -rf "$fendkit_installer_dir"' EXIT
  curl -fsSL https://raw.githubusercontent.com/vincentsch/fendkit/main/install.sh -o "$fendkit_installer_dir/install.sh" || exit
  bash "$fendkit_installer_dir/install.sh"
); then
  export PATH="$HOME/.local/bin:$PATH"
  fendkit --version
  fendkit demo
fi
```

The installer checks SHA-256 before replacing an existing installation.
It downloads assets from GitHub Releases without calling the GitHub API.
It installs into `~/.local/bin` on Linux and macOS, or Windows with a compatible
Bash. The script is downloaded into a temporary directory, then removed.
The demo uses a bundled fictional plugin and makes online vulnerability lookups.
Use `fendkit demo --offline` to skip those requests; it exits 11 because lookup
evidence is missing. If no release is available, the installer says so.

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

## Other installation settings

To choose another directory or pin a tag, replace the `bash` line in the install
block above with:

```bash
INSTALL_DIR="$HOME/bin" FENDKIT_VERSION=v0.1.0 bash "$fendkit_installer_dir/install.sh"
```

Then add that directory to PATH with `export PATH="$HOME/bin:$PATH"`.
The installer also prints the PATH command for your chosen directory.
It needs `curl` and either `sha256sum` or `shasum`. It never runs `sudo`.

For a mirror, set `FENDKIT_RELEASES_URL` on the same `bash` line.
Latest downloads use `<url>/latest/download/<asset>`. A selected tag uses
`<url>/download/<tag>/<asset>`, including for `checksums.txt`.

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
