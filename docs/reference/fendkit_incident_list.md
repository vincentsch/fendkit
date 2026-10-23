# fendkit incident list

List incidents with deadlines and submission status

Read saved incident records and calculate current deadlines locally.
No network calls or file changes.

Related commands:
  incident show
  incident new
  check

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
fendkit incident list
```

## Examples

```
fendkit incident list
fendkit incident list --json
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Related commands

- incident show
- incident new
- check
