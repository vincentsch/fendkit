# GitHub Action

The Fendkit GitHub Action runs Fendkit, a free, open-source CLI for a
software maker's Cyber Resilience Act evidence, on the release your job
builds. It runs the scan and the check, writes a job summary and uploads the
reports. It needs an Ubuntu runner. GitHub-hosted Ubuntu runners have all
the tools it uses. macOS and Windows runners are not supported.

A self-hosted Ubuntu runner needs these tools:

- Bash and curl
- sha256sum or shasum
- jq
- the GitHub CLI

Run `fendkit init` on your machine, review your answers and commit `cra.yml`.
Without that file the Action fails before it scans. CI never runs the
interview. Check out your project and build or download the product release
before the Action step.

The [example workflow](../examples/github-workflow.yml) covers pull requests
and release events. Reference the Action as `vincentsch/fendkit@v0.1.0` or pin
its commit. The `make release` in the example stands for your own build
command.

## Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `latest` | The Fendkit release tag, such as `v0.1.0`. |
| `working-directory` | `.` | Project root, relative to `GITHUB_WORKSPACE` or absolute. |
| `release` | omitted | Your product ZIP or folder, or a glob, relative to the project root. |
| `fail-on` | `policy` | `policy` fails on a policy failure or incomplete evidence. `never` keeps the reports without that verdict. |
| `attach-to-release` | `false` | `true` attaches the scan evidence on release events. On other events the log says why it skipped. |

`release` selects **your product**. `version` selects **Fendkit**. Without a
release input, the CLI uses `cra.yml` or looks for the release itself. A
literal folder or ZIP path may contain spaces or point to a sibling
directory, like `../dist/product.zip`. A glob has to match a single file.
With zero matches the log says what to build. With several matches it lists
them so you can narrow the pattern. A path that exists wins over glob
characters in its name. Quote the values in YAML when needed. The Action
passes them as data.

The outputs `scan-exit-code` and `check-exit-code` hold each command's exit
code. A command that did not run leaves its output empty. The log also shows
both codes. A fatal scan leaves the check code empty.

The installer checks the downloaded checksum and uses a temporary directory
on the runner. `latest` uses the installer's latest route, a pinned version
its tag route. When the installation fails, the log keeps the diagnostic. The
scan sends package names and versions to OSV.dev and downloads CISA KEV. Those
details can reveal information about your product.

## Reports and failure policy

The Action runs `scan --no-prompt` and then `check --ci --no-prompt`. Both get
the resolved project root as `--dir`. Scan also gets the resolved release path
when you supplied one.

After scan exit 0 or 11, it collects `inventory.json`, `sbom.cdx.json`,
`vulnerabilities.json` and `vulnerabilities.md`, plus `vex.openvex.json` when
it exists. After check exit 0, 10 or 11, it adds `status.md` and
`status.html`. A missing required report fails the collection. Only these
files go into a fresh artifact directory, which a pinned artifact Action
uploads before the verdict. Other files under `cra/reports/` stay out of the
upload.

| CLI results | `policy` | `never` |
| --- | --- | --- |
| Scan 0 and check 0 | Succeed | Succeed |
| Check 10, or either command 11, without an operational error | Fail | Succeed |
| Any other nonzero code, including 1, 2 or 5 | Fail | Fail |

A scan exit other than 0 or 11 stops check, collection and attachment. The
summary says `Fendkit scan failed (exit N); no reports from this run`.
Committed reports stay untouched and are not presented as the result of this
run.

An unexpected check code keeps the scan reports available for upload and
attachment. Both status pages are left out, including old copies. The summary
says `Fendkit check failed (exit N); status reports omitted from this run`.
The Action fails after the collection and any eligible attachment, under
either policy. An invalid input or an error in any other step also fails the
job under either policy. Incomplete lookups stay visible in the summary and
the reports.

## Release attachments and permissions

A pull-request check needs only `contents: read`. The release attachment job
needs `contents: write`. The Action takes `GH_TOKEN` from `github.token`.
There is no token input. Keep the privileged release job separate from
untrusted pull-request code, as in the example. Do not use
`pull_request_target` to build an untrusted product with a release token.

On a release event, the Action uploads to that event's tag and repository
with `gh release upload --clobber`. It attaches the current SBOM and the
current VEX, when there is one. No VEX is normal when the saved triage does
not match the current findings. The attachment runs before the verdict, also
for incomplete scans and operational check failures. A fatal scan or a
missing current SBOM prevents it.

A rerun replaces only the files it supplies. If a rerun has no local VEX, an
older VEX asset stays on the release. Remove such an outdated asset yourself.
The Action never deletes release assets.

## Review the evidence locally

Use the [README quickstart](../README.md#start-on-your-plugin) for the first
interview. [cra.yml](cra-yml.md) holds your saved answers.
[Inventory](inventory.md) explains the release boundary. Read
[status items](status-items.md) and [vulnerabilities](vulnerabilities.md)
before you choose a failure policy. The Action does not mark
[documents](documents.md) reviewed and does not file
[incident reports](incidents.md). Review the documents on your machine.
