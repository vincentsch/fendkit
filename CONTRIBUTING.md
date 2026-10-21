# Contributing

Use the Go version in `go.mod`. Run these checks before sending a change:

```bash
make build test race lint docs-check conformance
make build-all VERSION=v0.1.0
bash scripts/test-install.sh
```

`make build` writes the native executable into `bin/` with CGO disabled.
`make build-all` writes six binaries and `checksums.txt` into `dist/`.
`make clean` removes those build outputs. Untagged builds use `dev`; release
builds receive `VERSION` explicitly. `COMMIT` can override the source revision.

Change command definitions first, then run `make docs` and commit the generated
reference. Generation and pruning stay inside `docs/reference/`. The local renderer enriches
rungrad pages with long help and Cobra flag signatures. Write and check compare
the same generated content.
`make docs-check` reports drift without changing files. Keep handwritten pages
and images outside that directory. Conformance uses rungrad at the pinned
version and a fresh offline demo; it needs no advisory service.
The installer checks use Python 3 and a temporary loopback HTTP server.

Write plain English with short sentences and concrete next commands.
Explain terms when readers first need them. Describe drafts and evidence;
do not claim a product meets the law or promise a security outcome.
Test behavior that people rely on, including exit codes and failure messages.
Keep credentials, personal paths and machine-specific output out of source.
See [RELEASE.md](RELEASE.md) for publication checks and
[the command reference](docs/commands.md) for the CLI surface.
