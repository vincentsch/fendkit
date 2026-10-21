# Fendkit

Prepare your EU Cyber Resilience Act evidence and see what still needs doing.

Fendkit checks the third-party components in your software release,
writes draft evidence documents, and shows what still needs your review.
It starts with WordPress plugins and themes, Composer packages and npm packages.

[Website](https://www.fendkit.com) · [Guides](#read-the-guides) · [AGENTS.md](AGENTS.md)

## Start with your coding agent

Copy this into Claude Code, Codex or another coding agent in your product:

```text
Get this project ready for the EU Cyber Resilience Act with Fendkit.
Use https://github.com/vincentsch/fendkit: read its AGENTS.md and follow
the steps. Ask me the questions only I can answer, and show me what is still
missing at the end.
```

The agent follows [AGENTS.md](AGENTS.md), shows the inventory first, and asks
about your role, contact, support period and product categories. You can leave
answers unknown. With an existing `cra.yml`, it uses your saved answers and
runs the release check directly.

## Install and try the example

Install the checked release with Bash on Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/vincentsch/fendkit/main/install.sh -o install.sh
bash install.sh
fendkit --version
fendkit doctor
fendkit demo
```

See [installation](docs/install.md) for PATH, pinned versions, Go installation
and native Windows downloads. If no release is available, the installer says
so. Doctor checks setup and provider connections; a missing profile is normal
before init. The demo uses a bundled fictional plugin in a new directory.

Live lookups from the demo, captured on 21 October 2026 (Europe/Berlin).
The scan time shown is in UTC. Both themes show the same complete scan;
drafts still need review.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/status-dark.png">
  <img src="docs/media/status-light.png" alt="Fendkit live demo report with five update steps, 26 open advisory groups in shipped or possibly shipped components, and all 13 checklist rows. Drafts need review.">
</picture>

To try without vulnerability lookups:

```bash
fendkit demo --offline --out ./example
```

Offline runs exit 11 with `incomplete (lookups did not run)` in the header.
The first next step explains how to get complete evidence. Open the printed
`status.html` path in your browser and `cra/README.md` for drafts and reports.

## Start on your plugin

From your plugin root, point init at the ZIP or folder you ship:

```bash
fendkit init --release ../dist/plugin.zip
```

Init shows what it found before the interview. Composer runtime packages,
npm dependencies and recognised bundled JavaScript libraries form the
[inventory](docs/inventory.md). The release file tells the tool what ships;
build tools that stay outside it do not become shipped dependencies.
Without a release, some shipping decisions remain unknown.

Init writes `cra.yml`, draft documents in `cra/`, a root `SECURITY.md`, and
reports in `cra/reports/`. Complete and review the drafts yourself.
It refuses to replace an existing profile. On later releases, run each command
in order. Continue after scan exit 0 or 11. For any other scan exit, stop
and repair the error before running docs or check:

```bash
fendkit scan --release ../dist/plugin.zip
fendkit docs
fendkit check
```

A saved `product.release` is used when you omit `--release`. Keep it current.
Changing that setting makes earlier evidence stale, even if the old artifact
still exists. Follow the recovery command in check to scan the new boundary.
Scans reject conflicting detected product identities or versions before
replacing reports. Missing comparable identity metadata is shown as unverified.
Composer package files without installed metadata stay possibly shipped with
an unknown release version; the repository lockfile cannot establish it.
Docs preserves existing maker documents and refreshes the index. Check writes
Markdown and HTML status pages. Exit 10 means a policy failure; 11 means
missing, incomplete or stale evidence without a higher-priority policy failure.
Exit 0 does not mean every draft has been reviewed.
See [all status rules](docs/status-items.md).

A full captured live demo check (21 October 2026 Europe/Berlin,
21 October 2026 UTC), from the same run as the images:

```text
Fendkit  Acme Booking 2.3.1 (WordPress plugin)   scan: 2026-10-21 12:03 UTC, complete

Next
  1. Update guzzlehttp/guzzle from 7.4.0 to 7.15.2 in vendor/guzzlehttp/guzzle (13 advisories).
  2. Update jQuery Validation from 1.19.1 to 1.20.0 in assets/js/vendor/jquery.validate.min.js (4 advisories).
  3. Update moment.js from 2.24.0 to 2.29.4 in assets/js/vendor/moment.min.js (2 advisories).

Status
  evidenced      Role, Classification, SBOM
  needs review   Security contact, Disclosure policy, Known vulnerabilities,
                 Support period, User information, Risk assessment, Technical
                 documentation, EU declaration of conformity, Incident readiness
  not applicable Open incidents (none)

Full status: cra/reports/status.html
Not legal advice. Fendkit helps you prepare; the decisions and the signature are yours.
```

The demo product and maker decisions are fictional. Its findings come from
actual advisory lookups. On your product, unknown decisions stay visible
until you make them.

## Keep it in your release routine

Commit your decisions and reviewed documents with your product. Build the
release first, scan it, refresh the document index with `fendkit docs`,
review [findings](docs/vulnerabilities.md), then run check.
The [GitHub Action](docs/github-action.md) runs the saved-profile checks on
Ubuntu and keeps reports even when the evidence needs attention.

For an actively exploited vulnerability or severe incident, use the
[incident commands](docs/incidents.md). They record your awareness time,
show reporting deadlines and prepare drafts. A person checks the live ENISA
form, files the report and records the submission. Fendkit does not file it.

## Read the guides

| Guide | What it explains |
| --- | --- |
| [CRA for plugin makers](docs/cra-for-plugin-makers.md) | Roles, dates and evidence obligations. |
| [Status items](docs/status-items.md) | Thirteen items, next actions and exit codes. |
| [Inventory](docs/inventory.md) | Detection, release boundaries and coverage gaps. |
| [Vulnerabilities](docs/vulnerabilities.md) | Sources, triage and product-specific VEX decisions. |
| [Documents](docs/documents.md) | Drafts, review and publication. |
| [Incidents](docs/incidents.md) | Awareness, deadlines and manual reporting. |
| [GitHub Action](docs/github-action.md) | Release checks, permissions and failure policy. |
| [cra.yml](docs/cra-yml.md) | Saved answers, manual components and unknowns. |
| [Commands](docs/commands.md) | Generated command and flag reference. |

## Privacy and limits

Online scans send package names and exact versions to OSV.dev, then fetch
advisory details and download CISA's Known Exploited Vulnerabilities catalog.
Those names and versions can reveal private product dependencies. Source code
and maker answers are not uploaded by Fendkit. Doctor sends an empty OSV
request and checks KEV headers. Offline scan/demo/init skip those lookups.
Installation downloads the installer, binaries and checksums from GitHub;
Go installation uses Go's configured module services. Your coding agent has
its own network and privacy settings.

Reports credit [OSV](https://osv.dev/), the
[GitHub Advisory Database](https://github.com/advisories) (CC-BY 4.0), and
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
The status HTML is self-contained, with no external fonts or trackers.

Findings cover third-party components, not your own code. Zero findings cannot
prove the absence of vulnerabilities. Offline or failed lookups leave evidence
incomplete. Expired or changed saved evidence is stale. pnpm and Yarn lockfiles
are detected but not parsed. Unrecognised bundles, unknown versions and modified
copies need your investigation.
There is no Go/Python dependency scan, container scan or notified-body procedure.
For open-source stewards, v0.1 runs the same checks but does not assess the
lighter Article 24 obligations.

Outputs are drafts. Fendkit gives no legal advice. You make the decisions,
review the documents and sign any final declaration yourself.

As checked on **20 October 2026**, manufacturer reporting obligations under
Article 14 apply from **11 September 2026**; the main obligations apply from
**11 December 2027** (Article 71). Read the
[Commission overview](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
and the [CRA guide](docs/cra-for-plugin-makers.md) for scope and sources.

## License

[MIT](LICENSE). See [contributing](CONTRIBUTING.md) to work on Fendkit itself.
