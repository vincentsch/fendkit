# fendkit triage

Record a decision and export product-specific VEX

## Usage

```
fendkit triage <advisory-id>
```

## Examples

```
fendkit triage GHSA-f2wf-25xc-69c9 --status under_investigation --reason 'Reviewing product usage'
fendkit triage GHSA-f2wf-25xc-69c9 --status not_affected --justification vulnerable_code_not_in_execute_path --reason 'The product does not use the affected code path'
```

## Flags

- `--component` Exact component purl with version from vulnerabilities.md
- `--justification` Required for not_affected: component_not_present, vulnerable_code_not_present, vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary, inline_mitigations_already_exist
- `--reason` Reason for the decision; for affected, describe the intended response (required)
- `--status` affected, not_affected, fixed, or under_investigation

## Output modes

human, json

## Changes state

This command changes state and honors `--dry-run`.
