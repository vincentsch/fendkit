# Review vulnerability findings

Online scan asks OSV.dev about package names and exact versions, fetches advisory
details, and downloads CISA's Known Exploited Vulnerabilities (KEV) catalog.
Package names and versions can reveal private dependencies. Offline scans skip
these requests and remain incomplete. See [privacy](../README.md#privacy-and-limits).

Reports retain attribution to [OSV](https://osv.dev/), the
[GitHub Advisory Database](https://github.com/advisories) under CC-BY 4.0,
and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Aliases group related advisory identifiers; KEV matching uses aliases too.
KEV means known exploitation is catalogued, not that your product was exploited.

## Read the reports

Open `cra/reports/vulnerabilities.md` for findings, affected components,
source links, fixed versions and triage. JSON supplies the same evidence for
tooling. Coverage gaps include unknown versions and modified copies.
Findings concern third-party components rather than your own code.
Zero findings cannot prove the absence of vulnerabilities.

A failed batch, advisory detail or KEV lookup makes the scan incomplete.
Reports are still written and scan returns 11. A stale scan, missing release
or mismatched report set also prevents current evidence in check. Use
`conformline doctor`, fix the cause and rerun `conformline scan`.
Do not describe a failed lookup as a clean result.

## Decide what a finding means for this product

Investigate the affected version, code path and your shipped copy. Numeric
fixed versions can suggest an update; unusual version schemes need review
of the linked source. Test updates in your product before replacing bundles.
Conformline does not update libraries for you.

The following is illustrative. Replace the advisory and exact component
package URL (purl) with values from your own saved report:

```bash
conformline triage GHSA-f2wf-25xc-69c9 --component 'pkg:npm/moment@2.24.0' --status under_investigation --reason 'Reviewing where this product uses the affected code'
```

Use `affected` with your intended response, `under_investigation` while checking,
`fixed` when the finding has been addressed, or `not_affected` with evidence.
Every decision requires a reason. `not_affected` also requires an OpenVEX
justification: `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`,
or `inline_mitigations_already_exist`. These are claims you must substantiate.

Triage requires `cra.yml` and readable saved findings. It saves an exact
advisory/component-version decision in the profile and immediately rewrites
the vulnerability reports and `vex.openvex.json`, without network access.
A decision for one dependency version does not excuse a later version.
No matching triage means no current VEX export. Keep decisions tied to this
product rather than copying them to unrelated products.

Run [check](status-items.md) after triage. Open KEV findings in shipped or
possibly shipped components fail policy. Ordinary findings still need review
even when check exits 0. If exploitation or a severe incident affects your
product, review [incident handling](incidents.md); advisory discovery alone
does not establish the maker's awareness time for a reportable event.
