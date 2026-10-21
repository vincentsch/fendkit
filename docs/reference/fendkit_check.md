# fendkit check

Show evidence status and the next actions

## Usage

```
fendkit check
```

## Examples

```
fendkit check
fendkit check --strict --ci
fendkit check --json
```

## Flags

- `--ci` Append Markdown status to GITHUB_STEP_SUMMARY when set
- `--strict` Treat missing applicable items as policy failures

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
