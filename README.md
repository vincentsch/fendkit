# Fendkit

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/fendkit-wordmark-dark.svg">
  <img src="docs/media/fendkit-wordmark-light.svg" alt="Fendkit" width="220" height="56">
</picture>

Fendkit is a free, open-source CLI for software makers who sell or distribute
software in the EU and have to prepare for the Cyber Resilience Act (CRA). It
lists the third-party components you ship, checks them for known
vulnerabilities and writes the documents the CRA asks for as drafts. Then it
shows you what is in place and what still needs your review.

It works with WordPress plugins and themes, and with Composer and npm packages.

[Website](https://www.fendkit.com) · [Guides](#read-the-guides) · [AGENTS.md](AGENTS.md)

## Start with your coding agent

Paste this into Claude Code or Codex, in the folder of your product. Other
coding agents can follow the same prompt:

```text
Get this project ready for the EU Cyber Resilience Act with Fendkit.
Use https://github.com/vincentsch/fendkit: read its AGENTS.md and follow
the steps. Ask me the questions only I can answer, and show me what is still
missing at the end.
```

The agent reads [AGENTS.md](AGENTS.md) and shows you what it found before it
asks anything. You answer the questions it cannot answer for you, like your
legal role and your support period. You can leave an answer unknown. When
there is a `cra.yml` already, the agent uses your saved answers and runs the
release check right away.

## Install and try the example

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
  fendkit doctor
  fendkit demo
fi
```

The installer checks the SHA-256 hash of the download. For another
directory or a pinned version, see the [installation guide](docs/install.md).
It also covers Windows without Bash and builds from source. Doctor checks your
setup and the connection to the advisory sources. Before init it reports a
missing `cra.yml`, which is normal. The demo copies a fictional plugin into a
new directory and runs the whole sequence on it.

This is the status report for the fictional Acme Booking plugin after online
lookups on 21 October 2026. The drafts still need review.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/status-dark.png">
  <img src="docs/media/status-light.png" alt="Fendkit status report for the Acme Booking demo: five update steps, 26 open advisory groups in shipped or possibly shipped components and all thirteen checklist rows. The drafts need review.">
</picture>

To run it without vulnerability lookups:

```bash
fendkit demo --offline --out ./example
```

An offline run exits 11 and says `incomplete (lookups did not run)` in the
header. Its first next step explains how to get complete evidence. Open the
printed `status.html` path in your browser, and `cra/README.md` for the
drafts and reports.

## Start on your plugin

From your plugin root, point init at the ZIP or folder you ship:

```bash
fendkit init --release ../dist/plugin.zip
```

Init shows what it found before the interview starts. The
[inventory](docs/inventory.md) lists your Composer and npm dependencies.
Fendkit also recognises a number of bundled JavaScript libraries by their
banners. The release file tells it what ships. A build tool that stays
outside the release does not become a shipped dependency. Without a release,
some shipping decisions stay unknown.

Init saves your answers in `cra.yml`. It writes the drafts into `cra/` and a
`SECURITY.md` into the root, and the reports into `cra/reports/`. You
complete and review the drafts yourself. Init refuses to replace an existing
profile. For each later release, run these three commands in this order.
Continue after scan exits 0 or 11. After any other scan exit, stop and fix
the error before you run docs or check:

```bash
fendkit scan --release ../dist/plugin.zip
fendkit docs
fendkit check
```

When you leave out `--release`, scan uses the saved `product.release`. Keep
it current. If check reports stale evidence, run the command it prints. The
[inventory guide](docs/inventory.md#the-release-boundary) explains how
Fendkit checks the release identity and what happens with unknown versions.
Docs keeps your existing documents and refreshes the index. Check writes the
status as Markdown and HTML. Exit 10 is a policy failure. Exit 11 means the
scan evidence is missing, incomplete or stale and nothing worse applies.
Exit 0 does not mean that you have reviewed every draft. See
[all status rules](docs/status-items.md).

This is the terminal output of an earlier online demo on 21 October 2026 at
12:03 UTC:

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

The findings come from live advisory lookups. On your own product, unknown
decisions stay visible until you make them.

## After each release

Commit your decisions and the reviewed documents with your product. After
each release build, run the three commands above. Read the
[findings](docs/vulnerabilities.md) and update your decisions where needed.
The [GitHub Action](docs/github-action.md) runs the same checks with your
saved profile on Ubuntu and keeps the reports, even when the evidence needs
attention.

When a vulnerability in your product is being exploited, or a severe incident
hits it, use the [incident commands](docs/incidents.md). Tell Fendkit when you
became aware. It calculates the reporting deadlines and prepares the drafts.
You check and submit the reports in ENISA's live form, then record the
submission in Fendkit.

## Read the guides

| Guide | What it explains |
| --- | --- |
| [CRA for plugin makers](docs/cra-for-plugin-makers.md) | Your role under the CRA, the dates and the evidence it asks for. |
| [Status items](docs/status-items.md) | The thirteen items, the next actions and the exit codes. |
| [Inventory](docs/inventory.md) | What Fendkit detects, the release boundary and the coverage gaps. |
| [Vulnerabilities](docs/vulnerabilities.md) | The sources, triage and VEX decisions for your product. |
| [Documents](docs/documents.md) | The drafts, your review and publication. |
| [Incidents](docs/incidents.md) | Awareness time, deadlines and filing by hand. |
| [GitHub Action](docs/github-action.md) | Release checks, permissions and the failure policy. |
| [cra.yml](docs/cra-yml.md) | Saved answers, manual components and unknowns. |
| [Commands](docs/commands.md) | The generated command and flag reference. |

## Privacy and limits

An online scan sends package names and exact versions to OSV.dev, fetches the
advisory details and downloads CISA's Known Exploited Vulnerabilities catalog.
Those names and versions can reveal private dependencies of your product.
Fendkit does not upload your source code or your answers. Doctor sends an
empty request to OSV.dev and checks that the KEV catalog answers. The
`--offline` flag on scan, demo and init skips the lookups. The installer
downloads from GitHub. A
Go install uses the module proxy your Go setup is configured for. Your coding
agent has its own network and privacy settings.

The reports credit [OSV](https://osv.dev/), the
[GitHub Advisory Database](https://github.com/advisories) (CC-BY 4.0) and
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
The status HTML is one self-contained file without external fonts or
trackers.

The findings cover third-party components. Fendkit does not check your own
code. Zero findings do not prove that there are no vulnerabilities. Offline
or failed lookups leave the evidence incomplete. Saved evidence that expired
or no longer matches is stale. Fendkit sees pnpm and Yarn lockfiles but does
not read them. A bundle it does not recognise needs your own investigation.
The same goes for an unknown version or a modified copy. It does not scan Go
or Python dependencies or container images, and it does not cover the
notified-body procedure. For an open-source steward, v0.1 runs the same
checks but does not assess the lighter Article 24 obligations.

Everything Fendkit writes is a draft. It gives no legal advice. The decisions
and the review are yours. You sign any final declaration yourself.

As checked on **20 October 2026**, the manufacturer reporting obligations
under Article 14 apply from **11 September 2026**. The main obligations
apply from **11 December 2027** (Article 71). Read the
[Commission overview](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
and the [CRA guide](docs/cra-for-plugin-makers.md) for scope and sources.

Built with [rungrad](https://rungrad.com).

## License

[MIT](LICENSE). See [contributing](CONTRIBUTING.md) if you want to work on
Fendkit itself.

Made by [Vincent Schmalbach](https://www.vincentschmalbach.com/).
