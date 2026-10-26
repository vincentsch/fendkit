# fendkit incident submitted

Record a person's filing in ENISA's platform

Records a filing only; nothing is sent. A recorded stage stops being overdue.
Recording notification submission recalculates the severe-incident final deadline.
--at accepts RFC 3339 or YYYY-MM-DD HH:MM in the local zone; defaults to now.
All times display in the incident's recorded time zone. Existing drafts are preserved.
Use --dry-run to preview without changing the record.

Related commands:
  incident show
  incident list
  check

## Flags

```text
      --at string      Recorded time; defaults to now (RFC 3339 or local YYYY-MM-DD HH:MM)
      --stage string   early-warning, notification, or final (required)
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
fendkit incident submitted <id>
```

## Examples

```
fendkit incident submitted inc-1 --stage early-warning
```

## Related commands

- incident show
- incident list
- check
