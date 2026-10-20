# conformline check

Show evidence status and the next actions

## Usage

```
conformline check
```

## Examples

```
conformline check
conformline check --strict --ci
conformline check --json
```

## Flags

- `--ci` Append Markdown status to GITHUB_STEP_SUMMARY when set
- `--strict` Treat missing applicable items as policy failures

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
