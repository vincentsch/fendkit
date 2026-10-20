# Read the status items

`conformline check` evaluates saved decisions, documents and scan reports.
It writes `cra/reports/status.md` and `status.html`; it does not do a network
lookup. Run [scan](reference/conformline_scan.md) first when evidence changes.

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
| Known vulnerabilities | Evidenced only with complete current evidence, no open shipped/possibly shipped advisory groups and no coverage gaps. Investigate findings and unknown or modified components. Triage with reasons, then rescan when needed. |
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

Check rejects mixed scan IDs, changed inventory digests, changed product
versions, missing releases and reports older than seven days as current
evidence. Restore the release or correct the version, then run scan again.
Saved finding counts still describe saved results, not current coverage.

Next actions prioritise reporting deadlines and known exploited findings,
then other findings, decisions and documents. The report lists up to five;
the terminal highlights three and wraps status groups to fit your terminal.
Open the full report for scope notes and detailed item explanations.

## Exit codes

| Result | Meaning |
| --- | --- |
| `0` | No configured failure; drafts may still need review. |
| `10` | An unresolved KEV finding in a shipped/possibly shipped component, an overdue reporting stage, or a missing item under `--strict`. |
| `11` | Incomplete or stale scan evidence, when no code-10 failure takes precedence. |
| Other nonzero | An operational or usage error; read the diagnostic and repair it. |

Ordinary advisory findings and unknown decisions need review but do not alone
fail the default policy. `--strict` fails missing items; it does not make every
needs-review state fail. Scan itself uses 0 for complete and 11 for incomplete,
not check's policy code. Init returns its final check code after scan/docs.
See [the check reference](reference/conformline_check.md) and
[Action failure policy](github-action.md#reports-and-failure-policy).
