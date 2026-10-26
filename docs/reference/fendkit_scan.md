# fendkit scan

Find dependencies and look up known vulnerabilities

Read WordPress headers, Composer and npm metadata, bundled JavaScript, and release ZIPs or folders.
Write inventory.json, sbom.cdx.json, vulnerabilities.json and vulnerabilities.md under cra/reports/.
Export vex.openvex.json when saved triage matches findings.
Lookups send package names, versions and advisory ids to OSV.dev, and download CISA KEV.
Package names and versions can reveal product information.
Exit 0 for complete lookups, 11 for offline or failed lookups.
Apply product settings and manual components from cra.yml.
A release flag overrides product.release; relative paths start at --dir.
Reject conflicting detected product identities or versions before replacing reports.
Missing comparable identity metadata is reported as unverified.
Changing the saved release setting makes earlier evidence stale.
Without either, use a single dist/ or build/ ZIP containing the product version.
Development packages bundled without recognizable evidence need a manual shipped correction or a move to dependencies.
Use --dry-run to preview the result without writing files.

## Flags

```text
      --offline          Skip vulnerability lookups and mark the scan incomplete
      --release string   Release ZIP or folder, relative to --dir (overrides product.release)
```

## Inherited flags

```text
      --config string   Path to the config file
      --dir string      Project root (default ".")
      --dry-run         Preview changes without performing them
      --json            Output stable JSON instead of the human view
      --no-prompt       Never block on an interactive prompt
      --quiet           Suppress non-essential output
```

## Usage

```
fendkit scan
```

## Examples

```
fendkit scan
fendkit scan --offline
fendkit scan --offline --dir ./my-plugin --json
fendkit scan --offline --dry-run
```
