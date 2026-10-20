# Release Conformline

Make the repository public before the first tag. GitHub build provenance
attestations for this release must work without an Enterprise account.
See [GitHub's attestation requirements](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

## Before tagging

Run the local checks with the Go version in `go.mod`:

```bash
make clean
make build test race lint docs docs-check conformance
make build-all VERSION=v0.1.0
bash scripts/test-install.sh
GOOS=windows go vet ./...
GOOS=darwin go vet ./...
actionlint
```

Review application files for secrets and personal paths. Execute the native
binary and inspect all six binary formats and checksums. Test an untagged
source build and local `go install ./cmd/conformline`; both should show `dev`.
The version display also includes a commit and the Go runtime version.

Promote `## Unreleased` in `CHANGELOG.md` to `## v0.1.0 - YYYY-MM-DD`, using
the release date, then add a new `## Unreleased` heading above it.
Check `bash scripts/release-notes.sh v0.1.0`. The release job fails when the
exact dated section is absent. Review and commit before making an annotated
tag. Publishing a tag starts release automation; do not move a public tag.

## What GitHub runs

The tag job calls the same CI definition as pushes and pull requests.
Ubuntu, macOS and Windows build and run the Go tests natively. Ubuntu also
runs formatting, vet, race tests, docs checks, conformance and installer tests.
Only after all CI jobs succeed does the release job build six assets with the
explicit tag version. It writes SHA-256 checksums, attests each binary, and
publishes the assets with the matching changelog section.

External Actions use commit SHA pins. CI has `contents: read` only.
The release job needs `contents: write`, `id-token: write` and
`attestations: write`. Repository Actions settings must allow these permissions.
The job uses the provided `GITHUB_TOKEN` and needs no stored personal token.

## Checks still needed on GitHub

Local validation cannot execute macOS or Windows binaries. Confirm their
native CI jobs, including executable lookup on Windows. Cross-vet does not
cover that behavior. The read-only Git shell-stub test runs on Linux and macOS;
Windows skips that single test because an extensionless stub cannot replace Git.

Before publishing, confirm repository visibility and Actions permissions.
After the first authorized tag, verify the six uploaded binaries, their hashes,
build attestations and the exact release notes. Test latest and pinned installs
against public GitHub, and a versioned `go install` against the public module.
No tag, hosted run, attestation or release has been created during local setup.
