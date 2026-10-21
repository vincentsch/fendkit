# fendkit incident new

Record an incident and create filing drafts

Requires cra.yml. Drafts use saved findings only, without network calls.
--aware accepts RFC 3339 or YYYY-MM-DD HH:MM in the local IANA time zone.
Without --aware, confirm the proposed current time with --confirm or yes at the prompt.
In non-interactive or JSON use, pass --aware or --confirm.
The recorded zone comes from TZ, the /etc/localtime link, or UTC.
Drafts are created once; incident show always gives the current deadlines.
Use --dry-run to preview without writing files.

Related commands:
  incident show
  incident list
  check

Output modes:
  human, json

## Flags

```text
      --advisory string   Advisory id or alias from saved findings (optional)
      --aware string      Maker's awareness time: RFC 3339 or YYYY-MM-DD HH:MM
      --confirm           Confirm the proposed current awareness time
      --title string      Short incident description (required)
      --type string       exploited-vulnerability or severe-incident (required)
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
fendkit incident new
```

## Examples

```
fendkit incident new --type exploited-vulnerability --title 'Active exploitation' --aware '2026-10-20T10:00:00+02:00'
fendkit incident new --type severe-incident --title 'Service disruption' --confirm
```

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.

## Related commands

- incident show
- incident list
- check
