# fendkit incident show

Show current deadlines and paths to filing texts

Show outstanding and submitted stages, remaining time and the four draft paths.
The final clock waits for a fix for exploited vulnerabilities. Severe incidents use
a provisional notification due time until actual submission is recorded.

Related commands:
  incident submitted
  incident fix-available
  incident list

Output:
  Shows text you can read in your terminal.
  Use --json to get JSON for scripts and other programs.

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
fendkit incident show <id>
```

## Examples

```
fendkit incident show inc-1
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Related commands

- incident submitted
- incident fix-available
- incident list
