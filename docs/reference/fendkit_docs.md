# fendkit docs

Create missing draft documents and refresh the index

Create missing documents from cra.yml and saved reports.
Preserve every existing evidence document, including SECURITY.md.
Replace the generated cra/README.md index on each run.
For not-in-scope, write only the index and preserve existing documents.
Use --dry-run to list changes without writing files.

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
fendkit docs
```

## Examples

```
fendkit docs
fendkit docs --dry-run --json
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Preview changes

This command makes changes. Use `--dry-run` to see what would change without changing anything.
