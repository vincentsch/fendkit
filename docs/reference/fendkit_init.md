# fendkit init

Record your decisions and prepare draft CRA documents

## Usage

```
fendkit init
```

## Examples

```
fendkit init
fendkit init --answers answers.yml --no-prompt --release dist/plugin.zip
fendkit init --offline --no-prompt
```

## Flags

- `--answers` Partial cra.yml with your interview answers
- `--offline` Skip vulnerability lookups and mark the scan incomplete
- `--release` Release ZIP or folder, relative to --dir

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
