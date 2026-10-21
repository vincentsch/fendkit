# fendkit init

Record your decisions and prepare draft CRA documents

Show the detected product and dependencies, then ask for your decisions.
Write cra.yml, scan dependencies and create missing draft documents.
Preserve supplied decision dates and explicit nulls; date only decided answers with omitted dates.
Classification answers must agree with selected categories.
Unknown answers stay unknown. An answers file is a partial cra.yml; null suppresses a question.
With --no-prompt, omitted maker decisions stay unknown. Detection still supplies product facts.
Lookups send package names, versions and advisory ids to OSV.dev and download CISA KEV.
Finish with the evidence status, even after incomplete lookups. Exit 10 for policy failures, 11 for incomplete or stale evidence; otherwise 0.
Refuse to replace cra.yml; use scan, docs and check after setup.
Use --dry-run to preview without writes, lookups or Git subprocesses.

Output modes:
  human, json

## Flags

```text
      --answers string   Partial cra.yml with your interview answers
      --offline          Skip vulnerability lookups and mark the scan incomplete
      --release string   Release ZIP or folder, relative to --dir
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
fendkit init
```

## Examples

```
fendkit init
fendkit init --answers answers.yml --no-prompt --release dist/plugin.zip
fendkit init --offline --no-prompt
```

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
