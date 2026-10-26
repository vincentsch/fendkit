# Vulnerability findings

Fendkit is a free, open-source CLI for software makers who have to prepare
Cyber Resilience Act evidence. An online scan sends the package names and
exact versions of your components to OSV.dev and downloads CISA's Known
Exploited Vulnerabilities (KEV) catalog. Those names and versions can reveal
private dependencies. An offline scan skips the requests and stays
incomplete.

See [privacy and limits](../README.md#privacy-and-limits) for the full list
of network requests.

The reports keep the attribution to [OSV](https://osv.dev/), the
[GitHub Advisory Database](https://github.com/advisories) under CC-BY 4.0 and
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Identifiers for the same advisory are grouped, even when a KEV entry matches.
A KEV match means that exploitation has been reported somewhere. It does not
mean that your product was exploited.

## Read the reports

Open `cra/reports/vulnerabilities.md`. It shows which components have
findings and which versions fix them. It links to the sources and shows your
saved triage decisions. The JSON report has the same evidence. Coverage gaps
are components with an unknown version and modified copies. The findings
cover third-party components. Fendkit does not check your own code. Zero
findings do not prove that there are no vulnerabilities.

If an advisory or KEV lookup fails, Fendkit still writes the reports, but
scan returns 11. Run `fendkit doctor` to check the connection, then run
`fendkit scan` again. Check also needs reports from the same scan, no older
than seven days, and access to the recorded release. Its next action says
what to fix. A failed lookup leaves the evidence incomplete.

## Decide what a finding means for this product

Check whether the copy you ship uses the affected code. Fendkit compares
numeric versions and suggests an update. For other version schemes, read the
linked advisory to find a fix. Test an update in your product before you
replace a bundled library. Fendkit does not update libraries for you.

The example uses a finding from the demo. Replace the advisory ID and the
component package URL (purl) with values from your own report:

```bash
fendkit triage GHSA-f2wf-25xc-69c9 --component 'pkg:npm/moment@2.24.0' --status under_investigation --reason 'Reviewing where this product uses the affected code'
```

The status is `affected` with your intended response, `under_investigation`
while you check, `fixed` once you have addressed it, or `not_affected` with
evidence. Every decision needs a reason. `not_affected` also needs an OpenVEX
justification: `component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary` or
`inline_mitigations_already_exist`. Keep the evidence for the justification
you choose.

Triage needs `cra.yml` with `manufacturer.name` set, and saved findings it
can read. It saves your decision for that advisory and component version in
the profile and rewrites the vulnerability reports and `vex.openvex.json`.
VEX (Vulnerability Exploitability eXchange) is a machine-readable record of
whether a vulnerability affects this product. Fendkit exports it only when
the saved triage matches the current findings. Triage makes no network
requests. A decision for one version does not carry over to a later version.
Keep the decisions tied to this product and do not copy them to another one.

Run [check](status-items.md) after triage. Open KEV findings in shipped or
possibly shipped components fail the policy. Ordinary findings still need
your review, even when check exits 0. If your product is affected by
exploitation or by a severe incident, read [incident handling](incidents.md).
Finding an advisory is not by itself the moment you became aware of a
reportable event.
