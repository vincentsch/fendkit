# fendkit demo

Try Fendkit on the bundled example plugin

Copy Acme Booking and its release ZIP into ./fendkit-demo/ or --out.
Refuse a non-empty output folder before writing anything.
Run init, scan, docs and check with bundled demo answers, without prompts or Git.
Lookups send package names, versions and advisory ids to OSV.dev and download CISA KEV.
Use --offline to skip all network requests. Failed lookups still produce reports.
Exit with the final check code: 10 for policy failures, 11 for incomplete evidence, otherwise 0.
Use --dry-run to preview without copying files or making network requests.

Output:
  Shows text you can read in your terminal.
  Use --json to get JSON for scripts and other programs.

## Flags

```text
      --offline      Skip vulnerability lookups and mark the scan incomplete
      --out string   Empty destination folder for the example and release ZIP (default "./fendkit-demo")
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
fendkit demo
```

## Examples

```
fendkit demo
fendkit demo --offline --out ./example
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.

## Preview changes

This command makes changes. Use `--dry-run` to see what would change without changing anything.
