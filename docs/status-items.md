# Read the status items

`fendkit check` evaluates saved decisions, documents and scan reports.
It writes `cra/reports/status.md` and `status.html` without network requests. Run [scan](reference/fendkit_scan.md) first when evidence changes.

## What the states mean

**Evidenced** means the tool found the record it checks. **Needs review**
means a decision, draft, finding or coverage gap needs attention. **Missing**
means a required local file or support date is absent. **Not applicable**
means the recorded role excludes that item, or there are no open incidents.
These are evidence states, not a judgment that the product meets the law.

For document items, an absent file is missing. An existing file needs review
until it has `status: reviewed`, a nonblank `reviewed_by`, a `reviewed_on`
date in YYYY-MM-DD form, and no `[[placeholders]]`. Metadata records your
review; the tool cannot judge its quality. See [document review](documents.md#record-your-review).

## The thirteen items

| Item | Judgment and next action |
| --- | --- |
| Role | Unknown needs review; a saved role is evidenced. Decide `role.answer` and revisit when your business changes. |
| Classification | Unknown needs review; a saved decision is evidenced. Decide categories from the product's core function. Important/critical decisions also show the unsupported assessment procedure notice. |
| Security contact | Both root `SECURITY.md` and `cra/security.txt` must pass document review; either missing makes the item missing. Publish the reviewed policy and security.txt over HTTPS. Local checks cannot verify publication. |
| Disclosure policy | Review `cra/disclosure-policy.md`, including your reporting and response process. |
| SBOM | Missing/unreadable SBOM is missing. Evidence must match the current scan and product version; unknown/mismatched versions or stale/incomplete evidence need review. Resolve version conflicts and rescan. |
| Known vulnerabilities | Evidenced only with complete current evidence, no open shipped/possibly shipped advisory groups and no coverage gaps. Investigate findings and unknown or modified components. Review cra/reports/vulnerabilities.md and record decisions with fendkit triage. |
| Support period | Unknown `support.end` is missing. Otherwise review `cra/support-period.md` and its rationale. |
| User information | Complete and review `cra/user-information.md`. |
| Risk assessment | Assess your own product and review `cra/risk-assessment.md`. The component scan does not do this assessment. |
| Technical documentation | Complete and review `cra/technical-documentation.md`, including design and test evidence. |
| EU declaration of conformity | Review `cra/eu-declaration-of-conformity.md`. It remains an unsigned draft; a review marker is not a signature or completed assessment. |
| Incident readiness | Complete and review `cra/incident-checklist.md`; check the current reporting form. |
| Open incidents | None is not applicable. Outstanding reporting stages need review; all stages recorded submitted are evidenced. Use `incident show` for current deadlines and file manually. |

For `not-in-scope`, all items except Role, SBOM and Known vulnerabilities become
not applicable. For `open-source-steward`, the same checks run with an explicit
notice that Article 24 is not assessed.

## Fresh evidence and next actions

The report header shows whether scan evidence is missing, incomplete, stale
or complete. JSON records the same state in `scan_state`; `scan_complete` is
true only for complete, current evidence. Reports show the original scan time.
There is no timestamp when the scan is missing.

| Evidence | State and header label |
| --- | --- |
| Inventory missing, unreadable, or without a scan ID, digest or time | `missing` |
| Incomplete offline scan | `incomplete (lookups did not run)` |
| Other incomplete scan | `incomplete (lookups failed)` |
| Missing/unreadable vulnerability report or SBOM, mixed provenance, or changed saved inventory digest | `incomplete (reports do not match)` |
| Local components or product version changed | `stale (components changed)` |
| Saved `product.release` changed | `stale (release configuration changed)` |
| Older scan lacks saved release configuration provenance | `stale (release provenance unavailable)` |
| Scan older than seven days | `stale (older than seven days)` |
| Recorded release missing, unreadable or different from the product | `stale (release unavailable)` |
| Source files or permissions prevent a local inventory rebuild | `stale (inventory unavailable)` |
| All completeness, provenance and freshness checks pass | `complete` |

The first matching row determines the header. Full reports explain every
problem, even when more than one applies. Fendkit compares file contents and
product versions with the saved scan. It uses the scan time to check age;
changing a file's modification time does not refresh evidence.
Finding counts come from that saved scan.

Next actions show urgent problems before a command to repair scan evidence.
The order is:

1. Overdue incident stages, known exploited findings and missing applicable
   items under `--strict`.
2. A recovery action for missing, incomplete or stale scan evidence.
3. Upcoming incident stages, in deadline order.
4. Component updates, ordered by severity, advisory count and name.
5. Findings without fixes, pending incident stages and decisions. Role is the
   first decision; draft reviews and other missing items follow their usual priorities.

Without a policy failure, scan recovery is the first action.

The recovery action explains what went wrong and what to fix before rescanning.
Incomplete lookups include advice about network access or `fendkit doctor`.
Scans record both the selected artifact and the saved `product.release` setting,
including an unset setting. While that setting is unchanged, recovery retains
the selected artifact as `fendkit scan --release '<path>'`, even when it came
only from a scan flag or is on another Windows drive. This preserves an
intentional override. Changing `product.release` makes the earlier scan stale;
recovery uses plain `fendkit scan` so the newly saved setting selects the release.
It must not repeat the old override.

Reports that do not record those release settings need a new scan. Recovery uses the
current saved release setting when present; otherwise it explicitly retains
the recorded release path, or uses plain scan if neither exists. Check, docs
and every status format evaluate these conditions without changing the profile.
Restore an unavailable release first, or pass a replacement explicitly with
`--release`. A source-file failure names the actual diagnostic rather than
blaming an otherwise readable release. Check still shows how to repair the scan when it exits 10.

The report lists up to five actions; urgent actions can fill that limit.
The terminal highlights three and wraps status groups to fit your terminal.
Full reports always retain scan causes, even when recovery falls below the
limit. Scan issues describe causes without repeating rescan commands. The
SBOM's scan-only action is omitted from the ranked list when recovery is
present; independent product-version repairs stay. The generated cra/README.md
shows the current evaluation while keeping saved report dates and links.

Full HTML and Markdown reports explain the common draft review procedure
once above the checklist. Rows name the files and specific problems. Ranked
next actions include the reviewer and date metadata so they work on their own.
JSON retains full actions and the common review procedure. Markdown documents
use front matter; security.txt uses comment metadata. File-specific problems,
security.txt expiry and publication instructions remain visible. Open the full
report for scope notes and detailed item explanations.

## Exit codes

| Result | Meaning |
| --- | --- |
| `0` | No configured failure; drafts may still need review. |
| `10` | An unresolved KEV finding in a shipped/possibly shipped component, an overdue reporting stage, or a missing item under `--strict`. |
| `11` | Missing, incomplete or stale scan evidence, when no code-10 failure takes precedence. |
| Other nonzero | An operational or usage error; read the diagnostic and repair it. |

Ordinary advisory findings and unknown decisions need review but do not alone
fail the default policy. `--strict` fails missing items; it does not make every
needs-review state fail. Scan itself uses 0 for complete and 11 for incomplete,
not check's policy code. Init returns its final check code after scan/docs.
See [the check reference](reference/fendkit_check.md) and
[Action failure policy](github-action.md#reports-and-failure-policy).
