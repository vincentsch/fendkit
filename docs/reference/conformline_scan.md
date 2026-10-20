# conformline scan

Find dependencies and look up known vulnerabilities

## Usage

```
conformline scan
```

## Examples

```
conformline scan
conformline scan --offline
conformline scan --offline --dir ./my-plugin --json
conformline scan --offline --dry-run
```

## Flags

- `--offline` Skip vulnerability lookups and mark the scan incomplete
- `--release` Release ZIP or folder, relative to --dir (overrides product.release)

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
