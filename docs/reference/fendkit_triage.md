# fendkit triage

Record a decision and export product-specific VEX

Select any advisory id or alias from the saved vulnerabilities report.
Requires cra.yml and manufacturer.name. No network requests are made.
Use --component with the exact versioned purl printed in vulnerabilities.md when several components match.
Every status requires --reason. For affected, describe the intended response.
not_affected also requires an OpenVEX --justification.
A new decision replaces the current decision for this advisory group and component version.
Use --dry-run to preview the decision without writing files.

Output:
  Shows text you can read in your terminal.
  Use --json to get JSON for scripts and other programs.

## Flags

```text
      --component string       Exact component purl with version from vulnerabilities.md
      --justification string   Required for not_affected: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist
      --reason string          Reason for the decision; for affected, describe the intended response (required)
      --status string          affected, not_affected, fixed, or under_investigation
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
fendkit triage <advisory-id>
```

## Examples

```
fendkit triage GHSA-f2wf-25xc-69c9 --status under_investigation --reason 'Reviewing product usage'
fendkit triage GHSA-f2wf-25xc-69c9 --status not_affected --justification vulnerable_code_not_in_execute_path --reason 'The product does not use the affected code path'
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Preview changes

This command makes changes. Use `--dry-run` to see what would change without changing anything.
