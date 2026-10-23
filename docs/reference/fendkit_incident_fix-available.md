# fendkit incident fix-available

Record when a fix or mitigation became available

For exploited vulnerabilities only. Starts the elapsed 14-day final-report clock.
--at accepts RFC 3339 or YYYY-MM-DD HH:MM in the local zone; defaults to now.
All times display in the incident's recorded time zone. Existing drafts are preserved.
Use --dry-run to preview without changing the record.

Related commands:
  incident show
  incident list
  check

Output:
  Shows text you can read in your terminal.
  Use --json to get JSON for scripts and other programs.

## Flags

```text
      --at string   Recorded time; defaults to now (RFC 3339 or local YYYY-MM-DD HH:MM)
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
fendkit incident fix-available <id>
```

## Examples

```
fendkit incident fix-available inc-1 --at '2026-10-21 12:00'
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Preview changes

This command makes changes. Use `--dry-run` to see what would change without changing anything.

## Related commands

- incident show
- incident list
- check
