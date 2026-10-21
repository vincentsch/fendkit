# Read the status items

`fendkit check` evaluates saved decisions, documents and scan reports.
It writes `cra/reports/status.md` and `status.html`; it does not do a network
lookup. Run [scan](reference/fendkit_scan.md) first when evidence changes.

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

The header and JSON `scan_state` distinguish missing, incomplete, stale and
complete evidence. `scan_complete` is true only for complete, current evidence.
Labels keep the saved scan time; a missing scan has no invented time.

| Evidence | State and header label |
| --- | --- |
| Inventory missing, unreadable, or without a scan ID, digest or time | `missing` |
| Incomplete offline scan | `incomplete (lookups did not run)` |
| Other incomplete scan | `incomplete (lookups failed)` |
| Missing/unreadable vulnerability report or SBOM, mixed provenance, or changed saved inventory digest | `incomplete (reports do not match)` |
| Local components or product version changed | `stale (components changed)` |
| Scan older than seven days | `stale (older than seven days)` |
| Recorded release missing, unreadable or different from the product | `stale (release unavailable)` |
| Source files or permissions prevent a local inventory rebuild | `stale (inventory unavailable)` |
| All completeness, provenance and freshness checks pass | `complete` |

The first matching row selects the header. Full reports keep every cause,
including stale causes when incomplete evidence takes precedence. Checks use
content digests, product versions and saved scan times, never file modification
times. Saved finding counts describe saved results, not current coverage.

Next actions put overdue incident stages first, then known exploited findings
and missing applicable items under `--strict`. One scan recovery action follows
these policy actions. With no policy failure, recovery is action 1. It precedes
upcoming incident stages in deadline order, then component updates ordered by
severity, advisory count and name. Findings without fixes, pending incident
stages and decisions follow; Role is the first decision. Draft reviews and
missing items keep their remaining priorities.

Recovery explains the scan problem and names local repairs before one rescan
command. It keeps network-access or doctor advice for incomplete lookups.
When the saved scan used a release, the command includes its quoted path as
`fendkit scan --release '<path>'`, even if cra.yml does not record it.
Restore an unavailable release first, or pass a replacement explicitly with
`--release`. A source-file failure names the actual diagnostic rather than
blaming an otherwise readable release. Recovery stays available with exit 10.

The report lists up to five actions; urgent actions can fill that limit.
The terminal highlights three and wraps status groups to fit your terminal.
Full reports always retain scan causes, even when recovery falls below the
limit. Scan issues describe causes without repeating rescan commands. The
SBOM's scan-only action is omitted from the ranked list when recovery is
present; independent product-version repairs stay. The generated cra/README.md
shows the current evaluation while keeping saved report dates and links.

Each checklist row names the files to review once. Markdown documents use
front matter; security.txt uses comment metadata. File-specific problems,
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
