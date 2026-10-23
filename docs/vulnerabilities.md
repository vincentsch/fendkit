# Review vulnerability findings

Online scans send package names and exact versions to OSV.dev for advisory
lookups. They also download CISA's Known Exploited Vulnerabilities (KEV) catalog.
Package names and versions can reveal private dependencies. Offline scans skip
these requests and remain incomplete. See [privacy](../README.md#privacy-and-limits).

Reports retain attribution to [OSV](https://osv.dev/), the
[GitHub Advisory Database](https://github.com/advisories) under CC-BY 4.0,
and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Reports group identifiers for the same advisory, including when matching KEV
entries. A KEV match means exploitation has been reported. It does not establish
that your product was exploited.

## Read the reports

Open `cra/reports/vulnerabilities.md` to see which components have findings
and which versions fix them. The report links to sources and shows your saved
triage decisions. JSON keeps the same evidence for other tools. Coverage gaps
include unknown versions and modified copies.
Findings concern third-party components rather than your own code.
Zero findings cannot prove the absence of vulnerabilities.

A failed batch, advisory detail or KEV lookup makes the scan incomplete.
Reports are still written and scan returns 11. A stale scan, missing release
or mismatched report set also prevents current evidence in check. Use
`fendkit doctor`, fix the cause and rerun `fendkit scan`.
Do not describe a failed lookup as a clean result.

## Decide what a finding means for this product

Investigate the affected version, code path and your shipped copy. Numeric
fixed versions can suggest an update; unusual version schemes need review
of the linked source. Test updates in your product before replacing bundles.
Fendkit does not update libraries for you.

This example uses a finding from the demo. Replace the advisory and exact component
package URL (purl) with values from your own saved report:

```bash
fendkit triage GHSA-f2wf-25xc-69c9 --component 'pkg:npm/moment@2.24.0' --status under_investigation --reason 'Reviewing where this product uses the affected code'
```

Use `affected` with your intended response, `under_investigation` while checking,
`fixed` when the finding has been addressed, or `not_affected` with evidence.
Every decision requires a reason. `not_affected` also requires an OpenVEX
justification: `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`,
or `inline_mitigations_already_exist`. Keep evidence for the justification you choose.

Triage requires `cra.yml` and readable saved findings. It saves an exact
advisory/component-version decision in the profile and immediately rewrites
the vulnerability reports and `vex.openvex.json`, without network access.
A decision for one dependency version does not apply to a later version.
Fendkit exports VEX only when saved triage matches current findings. VEX records
whether a vulnerability affects this product. Keep decisions tied to this
product rather than copying them to unrelated products.

Run [check](status-items.md) after triage. Open KEV findings in shipped or
possibly shipped components fail policy. Ordinary findings still need review
even when check exits 0. If exploitation or a severe incident affects your
product, review [incident handling](incidents.md); advisory discovery alone
does not establish the maker's awareness time for a reportable event.
