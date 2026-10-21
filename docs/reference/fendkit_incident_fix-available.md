# fendkit incident fix-available

Record when a fix or mitigation became available

## Usage

```
fendkit incident fix-available <id>
```

## Examples

```
fendkit incident fix-available inc-1 --at '2026-10-21 12:00'
```

## Flags

- `--at` Recorded time; defaults to now (RFC 3339 or local YYYY-MM-DD HH:MM)

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.

## Related commands

- incident show
- incident list
- check
