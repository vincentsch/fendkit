# fendkit check

Show evidence status and the next actions

Read cra.yml, documents and saved scan evidence without network calls.
Write cra/reports/status.md, status.html and refresh cra/README.md.
Exit 10 for overdue unsubmitted incident stages or unresolved shipped CISA KEV findings; --strict also fails on missing applicable items.
Otherwise exit 11 for missing, mixed, incomplete or stale scans; exit 0 for current evidence.
Scans become stale after seven days, inventory changes or product version changes.
--ci appends the Markdown report to GITHUB_STEP_SUMMARY when set.
Use --dry-run to evaluate without writing reports or the CI summary.

Output modes:
  human, json

## Flags

```text
      --ci       Append Markdown status to GITHUB_STEP_SUMMARY when set
      --strict   Treat missing applicable items as policy failures
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
fendkit check
```

## Examples

```
fendkit check
fendkit check --strict --ci
fendkit check --json
```

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
