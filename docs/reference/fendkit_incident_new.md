# fendkit incident new

Record an incident and create filing drafts

## Usage

```
fendkit incident new
```

## Examples

```
fendkit incident new --type exploited-vulnerability --title 'Active exploitation' --aware '2026-10-20T10:00:00+02:00'
fendkit incident new --type severe-incident --title 'Service disruption' --confirm
```

## Flags

- `--advisory` Advisory id or alias from saved findings (optional)
- `--aware` Maker's awareness time: RFC 3339 or YYYY-MM-DD HH:MM
- `--confirm` Confirm the proposed current awareness time
- `--title` Short incident description (required)
- `--type` exploited-vulnerability or severe-incident (required)

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.

## Related commands

- incident show
- incident list
- check
