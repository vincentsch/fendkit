# Release Fendkit

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
bash scripts/test-action.sh
GOOS=windows go vet ./...
GOOS=darwin go vet ./...
actionlint
```

Review application files for secrets and personal paths. Execute the native
binary and inspect all six binary formats and checksums. Test an untagged
source build and local `go install ./cmd/fendkit`; both should show `dev`.
The version display also includes a commit and the Go runtime version.

Promote `## Unreleased` in `CHANGELOG.md` to `## v0.1.0 - YYYY-MM-DD`, using
the release date, then add a new `## Unreleased` heading above it.
Check `bash scripts/release-notes.sh v0.1.0`. The release job fails when the
exact dated section is absent. Review and commit before making an annotated
tag. Publishing a tag starts release automation; do not move a public tag.

## What GitHub runs

The tag job calls the same CI definition as pushes and pull requests.
Ubuntu, macOS and Windows build and run the Go tests natively. Ubuntu also
runs formatting, vet, race tests, docs checks, conformance, installer tests
and consumer Action tests.
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
The repository, copied-prompt URL, binary downloads and
`vincentsch/fendkit@v0.1.0` Action reference need public access.
Release creation and these hosted checks remain open until actually run.
After the first authorized tag, verify the six uploaded binaries, their hashes,
build attestations and the exact release notes. Test latest and pinned installs
against public GitHub, and a versioned `go install` against the public module.
No tag, hosted run, attestation or release has been created during local setup.

## Consumer Action checks still needed on GitHub

Validate a published Action reference on Ubuntu with pull-request read permissions
and a release-only job granting `contents: write`. Confirm hosted artifact storage,
job summaries, named exit-code outputs and report availability after a policy failure.
Test both failure policies, incomplete lookups, operational failures and failed uploads.
Confirm release attachments use the event repository and tag, including SBOM-only
runs and VEX reruns with replacement. A missing local VEX must leave an older remote
asset alone; remove it manually when outdated. These hosted checks are unrun locally.
See [the Action guide](docs/github-action.md) and [consumer example](examples/github-workflow.yml).

## Public onboarding and further consumer checks

After publication, run the README's copied prompt from an unrelated maker
repository using only the public URL. Verify fresh installation via the latest
installer, a pinned installer, native Windows checksums and `go install @latest`.
The original local onboarding acceptance used an already built binary and did
not establish public access. The dated checks below now record public downloads. Follow the README commands with a
fresh maker profile and an existing profile, checking preservation of edited
documents and unknown decisions. Confirm the published Action reference from
that same product release. Reuse the hosted checks above for permissions,
uploads and attachments; local stubs do not replace hosted evidence.

## Public v0.1.0 verification, 2026-10-23

Published [fendkit v0.1.0](https://github.com/vincentsch/fendkit/releases/tag/v0.1.0)
from `6fbd826db7f9eaf9369e85c261b9e3225f6d306b`. The [release workflow](https://github.com/vincentsch/fendkit/actions/runs/39947703429)
passed Linux, macOS and Windows CI before the publishing job started. The release
contains six platform executables and `checksums.txt`. All six downloaded SHA-256
hashes matched. All six GitHub build attestations verified with `gh attestation verify`, the release workflow identity, tag ref and source digest pinned, and
`--deny-self-hosted-runners`.

On Linux amd64, latest and pinned (`v0.1.0`) public installers succeeded in fresh
temporary folders. The installed CLI's version and bundled demo were checked.
`go install github.com/vincentsch/fendkit/cmd/fendkit@v0.1.0` succeeded with an
initially empty module cache, the public Go proxy and checksum database. A separate
empty-cache `go install` with `@latest` also resolved v0.1.0 successfully. The
README agent prompt and `AGENTS.md` were fetched anonymously from GitHub and
matched the published source. Fetching the prompt does not establish a trial
with every supported coding agent.

The [native public-release smoke run](https://github.com/vincentsch/fendkit/actions/runs/39948044670)
passed on Linux amd64, macOS arm64 and Windows amd64: public native downloads,
checksum checks, latest and pinned installation where supported, version and demo
checks. Windows checked the `.exe` hash with PowerShell `Get-FileHash`. This is
native execution coverage for those three hosts; the other three assets were
cross-built and their checksums and provenance verified.
