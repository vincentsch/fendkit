# fendkit incident submitted

Record a person's filing in ENISA's platform

## Usage

```
fendkit incident submitted <id>
```

## Examples

```
fendkit incident submitted inc-1 --stage early-warning
```

## Flags

- `--at` Recorded time; defaults to now (RFC 3339 or local YYYY-MM-DD HH:MM)
- `--stage` early-warning, notification, or final (required)

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.

## Related commands

- incident show
- incident list
- check
