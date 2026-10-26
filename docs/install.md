# Install Fendkit

Fendkit is a free, open-source CLI for software makers who sell or distribute
software in the EU and have to prepare for the Cyber Resilience Act. It finds
the third-party components you ship, checks them for known vulnerabilities and
writes the CRA documents as drafts. It runs on Linux, macOS and Windows.

Install the latest release with Bash on Linux or macOS:

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

The installer downloads the binary and `checksums.txt` straight from GitHub
Releases, without the GitHub API. It checks the SHA-256 hash before it
replaces an installed version. It installs into `~/.local/bin`. On Windows it
works in Git Bash or another Bash. The script itself lands in a temporary
directory and is removed afterwards.

`fendkit demo` copies a fictional plugin into `./fendkit-demo/` and runs the
whole sequence on it, with online vulnerability lookups. `fendkit demo
--offline` skips those lookups. The demo then exits 11, because the evidence
is incomplete without them.

## Run it on your product

Go to your product's root and point init at the ZIP or folder you ship:

```bash
fendkit doctor
fendkit init --release ../dist/plugin.zip
```

Doctor checks your setup and the connection to OSV.dev and CISA. Before init
there is no `cra.yml` yet. Doctor says so, and that is normal. Init shows what
it found before it asks you anything. It saves your answers in `cra.yml`,
writes the drafts and the reports, and leaves unknown answers visible for
later. `cra/README.md` is the index of all documents. `cra/reports/status.html`
shows the next actions.

To run Fendkit from another directory, add `--dir /path/to/product` to each
command. A relative release path then counts from that product directory, not
from the directory your shell is in. Absolute paths also work.

For each later release, keep `product.release` in `cra.yml` current and run:

```bash
fendkit scan
fendkit docs
fendkit check
```

Run docs and check after scan exits 0 (complete) or 11 (incomplete). Any
other scan exit is an error. Stop and fix it first. Pass
`--release ../dist/plugin.zip` to scan only when you want to override the
saved release. Check exits 10 for a policy failure. It exits 11 when the scan
evidence is missing, incomplete or stale and nothing worse applies. Exit 0
does not mean you have reviewed the drafts. Fendkit gives no legal advice.
See [status items](status-items.md) and
[privacy and limits](../README.md#privacy-and-limits).

## Native Windows

Download `fendkit-windows-amd64.exe` or `fendkit-windows-arm64.exe` and
`checksums.txt` from the [release](https://github.com/vincentsch/fendkit/releases).
In PowerShell, compare the SHA-256 hash with the line for that file in
`checksums.txt`:

```powershell
Get-FileHash .\fendkit-windows-amd64.exe -Algorithm SHA256
```

When the hashes match, rename the file to `fendkit.exe` and put it in a
directory on PATH. `fendkit --version` shows that it works.

## Other installation settings

To install into another directory or pin a version, replace the `bash` line
in the block above with:

```bash
INSTALL_DIR="$HOME/bin" FENDKIT_VERSION=v0.1.0 bash "$fendkit_installer_dir/install.sh"
```

Then add that directory to PATH with `export PATH="$HOME/bin:$PATH"`. The
installer prints this command for the directory you chose. It needs `curl`
and either `sha256sum` or `shasum`. It never runs `sudo`.

For a mirror, set `FENDKIT_RELEASES_URL` on the same `bash` line. The latest
release is downloaded from `<url>/latest/download/<asset>`. A pinned tag uses
`<url>/download/<tag>/<asset>`, for the binary and for `checksums.txt`.

## Build from source

Use the Go version in `go.mod`. `make build` writes `bin/fendkit`.
`go install ./cmd/fendkit` installs into your Go bin directory. A build from
an untagged checkout reports the version `dev`. Once a tag is public,
`go install github.com/vincentsch/fendkit/cmd/fendkit@v0.1.0` reports that
module version.

With Go and access to the public module, you can also install the latest
tagged version:

```bash
go install github.com/vincentsch/fendkit/cmd/fendkit@latest
```

If you download a binary by hand, compare its SHA-256 hash with
`checksums.txt` as in the Windows section. The
[README](../README.md#install-and-try-the-example) has the complete first run.
[AGENTS.md](../AGENTS.md) has the steps for a coding agent.
