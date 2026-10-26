# Status items and exit codes

`fendkit check` shows a software maker where their Cyber Resilience Act
evidence stands. It is part of Fendkit, a free, open-source CLI. Check reads
your saved decisions, your documents and the scan reports and writes
`cra/reports/status.md` and `status.html`. It makes no network requests.

Run [scan](reference/fendkit_scan.md) first when the evidence has changed.

## What the states mean

**Evidenced** means Fendkit found the record it checks for. **Needs review**
means a decision, a draft, a finding or a coverage gap needs your attention.
**Missing** means a required local file or the support end date is absent.
**Not applicable** means your recorded role excludes the item, or there are no
open incidents. These are evidence states. They are not a judgment that your
product meets the law.

For the document items, an absent file is missing. An existing file needs
review until it has `status: reviewed`, a non-blank `reviewed_by`, a
`reviewed_on` date in YYYY-MM-DD form and no `[[placeholders]]` left. That
metadata records that you reviewed the file. Fendkit cannot judge the quality
of your review. See [record your review](documents.md#record-your-review).

## The thirteen items

| Item | What Fendkit checks and what to do |
| --- | --- |
| Role | Unknown needs review. A saved role is evidenced. Decide `role.answer` and look at it again when your business changes. |
| Classification | Unknown needs review. A saved decision is evidenced. Decide the categories from your product's core function. An important or critical decision also shows a notice that Fendkit does not prepare the assessment procedure. |
| Security contact | Root `SECURITY.md` and `cra/security.txt` both have to pass the document review. If either file is absent, the item is missing. Publish the reviewed policy and security.txt over HTTPS. A local check cannot see whether you published them. |
| Disclosure policy | Review `cra/disclosure-policy.md`, including how you receive and answer reports. |
| SBOM | An absent or unreadable SBOM is missing. The SBOM has to belong to the current scan and product version. An unknown or mismatched version, or stale or incomplete evidence, needs review. Resolve version conflicts and scan again. |
| Known vulnerabilities | Evidenced only with complete, current evidence, no open advisory groups in shipped or possibly shipped components and no coverage gaps. Look into the findings and into unknown or modified components. Read `cra/reports/vulnerabilities.md` and record your decisions with `fendkit triage`. |
| Support period | An unknown `support.end` is missing. Otherwise review `cra/support-period.md` and the reasons in it. |
| User information | Complete and review `cra/user-information.md`. |
| Risk assessment | Assess your own product and review `cra/risk-assessment.md`. The component scan is not that assessment. |
| Technical documentation | Complete and review `cra/technical-documentation.md`, including design and test evidence. |
| EU declaration of conformity | Review `cra/eu-declaration-of-conformity.md`. It stays an unsigned draft. The review marker is not a signature and not a completed assessment. |
| Incident readiness | Complete and review `cra/incident-checklist.md`, and check the current reporting form. |
| Open incidents | No incidents is not applicable. An outstanding reporting stage needs review. When every stage is recorded as submitted, the item is evidenced. `incident show` gives the current deadlines. You file the reports yourself. |

With the role `not-in-scope`, every item except Role, SBOM and Known
vulnerabilities becomes not applicable. With `open-source-steward`, the same
checks run as for a manufacturer, with a notice that Article 24 is not
assessed.

## Fresh evidence and next actions

The report header says whether the scan evidence is missing, incomplete,
stale or complete. The JSON report has the same state in `scan_state`.
`scan_complete` is true only for complete, current evidence. The reports show
the time of the original scan. When the scan is missing, there is no
timestamp.

| Evidence | Header label |
| --- | --- |
| Inventory missing, unreadable, or without a scan ID, digest or time | `missing` |
| Incomplete offline scan | `incomplete (lookups did not run)` |
| Other incomplete scan | `incomplete (lookups failed)` |
| Vulnerability report or SBOM missing or unreadable, reports from different scans, or the saved inventory digest changed | `incomplete (reports do not match)` |
| Local components or the product version changed | `stale (components changed)` |
| Saved `product.release` changed | `stale (release configuration changed)` |
| An older scan without saved release settings | `stale (release provenance unavailable)` |
| Scan older than seven days | `stale (older than seven days)` |
| Recorded release missing, unreadable or different from the product | `stale (release unavailable)` |
| Source files or permissions prevent a local inventory rebuild | `stale (inventory unavailable)` |
| All checks pass | `complete` |

The first matching row sets the header. The full reports explain every
problem, even when several apply. Fendkit compares file contents and product
versions with the saved scan. Age counts from the scan time, so touching a
file's modification time does not refresh anything. The finding counts come
from that saved scan.

Next actions put urgent problems first, then the command that repairs the
scan evidence. The order is:

1. Overdue incident stages, findings from the known exploited vulnerabilities
   catalog, and under `--strict` missing applicable items.
2. A recovery action for missing, incomplete or stale scan evidence.
3. Upcoming incident stages, earliest deadline first.
4. Component updates, ordered by severity, then advisory count, then name.
5. Findings without a fix, pending incident stages and decisions. Role is the
   first decision. Draft reviews and other missing items follow in their
   usual order.

Without a policy failure, the recovery action comes first.

The recovery action says what went wrong and what to fix before you scan
again. For incomplete lookups it points to your network access or to
`fendkit doctor`. Each scan records which release file it used and what
`product.release` was at the time, even when the setting was empty. As long
as that setting is unchanged, the recovery command repeats the same release
as `fendkit scan --release '<path>'`. That holds even when the path came only
from a scan flag or lies on another Windows drive, so an override you chose
on purpose is kept. Once you change `product.release`, the earlier scan is
stale and the recovery command is a plain `fendkit scan`, so the new saved
setting picks the release.

A report from an older scan that did not record these settings needs a new
scan. Check, docs and all report formats evaluate this without changing your
profile. If the release file is gone, restore it first or pass a replacement
with `--release`. When a source file cannot be read, the message names that
file instead of blaming a readable release. Check shows the repair command
even when it exits 10.

The report lists up to five actions, and urgent ones can take all five slots.
The terminal shows three and wraps the status groups to your terminal width.
The full reports always keep the scan causes, even when the recovery action
did not make the list. Each checklist row names its files and the specific
problem, and the HTML and Markdown reports explain the review procedure once,
above the checklist. A ranked next action names the reviewer and date fields,
so it makes sense on its own. The generated `cra/README.md` shows the current
evaluation and keeps the saved report dates and links. The full report also
has the scope notes and the detailed explanation of each item.

## Exit codes

| Result | Meaning |
| --- | --- |
| `0` | No configured failure. Drafts can still need review. |
| `10` | An unresolved finding from the known exploited vulnerabilities catalog in a shipped or possibly shipped component, an overdue reporting stage, or a missing item under `--strict`. |
| `11` | Missing, incomplete or stale scan evidence, when no code 10 failure takes precedence. |
| Other nonzero | An operational or usage error. Read the message and fix the cause. |

Ordinary advisory findings and unknown decisions need review, but on their
own they do not fail the default policy. `--strict` fails missing items. It
does not turn every needs-review state into a failure. Scan itself never
returns 10. It uses 0 for complete and 11 for incomplete. Init ends with the
check and returns its code. See [the check reference](reference/fendkit_check.md)
and the [Action failure policy](github-action.md#reports-and-failure-policy).
