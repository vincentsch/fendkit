# fendkit scan

Find dependencies and look up known vulnerabilities

## Usage

```
fendkit scan
```

## Examples

```
fendkit scan
fendkit scan --offline
fendkit scan --offline --dir ./my-plugin --json
fendkit scan --offline --dry-run
```

## Flags

- `--offline` Skip vulnerability lookups and mark the scan incomplete
- `--release` Release ZIP or folder, relative to --dir (overrides product.release)

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
