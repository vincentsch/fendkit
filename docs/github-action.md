# Check a product release in GitHub Actions

Conformline scans your product release, writes a job summary and uploads its
reports. Use an Ubuntu runner with Bash, curl, checksum tools, jq and GitHub
CLI available. GitHub-hosted Ubuntu runners include these tools. macOS and
Windows runners are not supported by this Action.

Run `conformline init` locally, review your answers and commit `cra.yml`.
The Action fails before scanning if that file is missing. CI does not run
the interview. Check out your project and build or download its product
release before calling the Action.

See the [consumer example](../examples/github-workflow.yml) for pull requests
and release events. Use `vincentsch/conformline@v0.1.0` or pin its commit.
The example's `make release` is a placeholder for your own product build.

## Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `version` | `latest` | Conformline release tag, such as `v0.1.0`. |
| `working-directory` | `.` | Project root relative to `GITHUB_WORKSPACE`, or an absolute directory. |
| `release` | omitted | Product ZIP/folder path or glob relative to that project root. |
| `fail-on` | `policy` | `policy` fails on policy or incomplete evidence; `never` suppresses only those verdicts. |
| `attach-to-release` | `false` | `true` attaches scan evidence on release events; other events log why attachment was skipped. |

`release` selects **your product**. `version` selects **Conformline**.
An omitted release lets the CLI use `cra.yml` or discover the release.
A literal folder or ZIP may include spaces or sibling paths such as
`../dist/product.zip`. A glob must match one file. Zero matches explain what
to build; multiple matches are listed for you to narrow the pattern.
Existing literal paths take precedence over wildcard characters in their names.
Quote input values in YAML when needed; the Action passes them as data.

Named outputs `scan-exit-code` and `check-exit-code` contain each command's
numeric result. A command that did not run has an empty output. The logs also
show both codes. A fatal scan exposes its code and leaves the check code empty.

The installer verifies the downloaded checksum and uses a runner temporary
directory. `latest` uses the installer's latest route; a pinned version uses
its tag route. Installation failures keep their diagnostic output in the log.
The scan sends package names and versions to OSV.dev and downloads CISA KEV.
These details can reveal information about your product.

## Reports and failure policy

The Action runs `scan --no-prompt`, followed by `check --ci --no-prompt`.
Both receive the resolved project root as `--dir`; scan also receives the
resolved literal release path when you supply one.

After scan exit 0 or 11, it collects `inventory.json`, `sbom.cdx.json`,
`vulnerabilities.json` and `vulnerabilities.md`, plus `vex.openvex.json` when
present. Check exit 0, 10 or 11 also collects `status.md` and `status.html`.
Missing required reports fail collection. Only these files go into a fresh
artifact directory, uploaded with a pinned artifact Action before the verdict.
Other files under `cra/reports/` stay out of the upload.

| CLI results | `policy` | `never` |
| --- | --- | --- |
| Scan 0 and check 0 | Succeed | Succeed |
| Check 10 or either command 11, without an operational error | Fail | Succeed |
| Unexpected nonzero code, including 1, 2 or 5 | Fail | Fail |

A scan exit other than 0 or 11 stops check, collection and attachment.
The summary says `Conformline scan failed (exit N); no reports from this run`.
Committed reports remain untouched and are not presented as current output.

An unexpected check code keeps the scan reports available for upload and
attachment. Both status pages are omitted, including old copies. The summary
says `Conformline check failed (exit N); status reports omitted from this run`.
The Action fails after collection and eligible attachment under either policy.
Invalid inputs, installation, collection, upload and attachment errors also fail
under either policy. Incomplete lookups remain visible in the summary and reports.

## Release attachments and permissions

Pull-request checks need only `contents: read`. The release attachment job
needs `contents: write`. The Action supplies `GH_TOKEN` from `github.token`;
there is no token input. Keep privileged release jobs separate from untrusted
pull-request code, as shown in the example. Do not use `pull_request_target`
to run an untrusted product build with a release token.

On a release event, the Action uses that event's tag and repository with
`gh release upload --clobber`. It supplies the current SBOM and any current VEX.
No VEX is normal when saved triage does not match current findings. Attachment
runs before the verdict, including incomplete scans and operational check
failures. A fatal scan or missing current SBOM prevents attachment.

Reruns replace only the files supplied by that invocation. If a rerun has no
local VEX, an older remote VEX asset remains. Remove that outdated release
asset manually. The Action never deletes release assets.

## Review the evidence locally

Use [the README quickstart](../README.md#start-on-your-plugin) for the first
interview. [cra.yml](cra-yml.md) holds saved answers; [inventory](inventory.md)
explains release boundaries. Read [status items](status-items.md) and
[vulnerabilities](vulnerabilities.md) before choosing a failure policy.
Reports cover third-party components rather than your own code. Zero findings
cannot prove the absence of vulnerabilities. Outputs are drafts and give no
legal advice. Review [documents](documents.md) locally; the Action does not
mark them reviewed or file [incident reports](incidents.md).
