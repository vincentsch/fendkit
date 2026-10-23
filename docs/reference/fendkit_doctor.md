# fendkit doctor

Check project setup and advisory connections

Check the repository, ecosystems, lockfile coverage, release and cra.yml.
Check OSV.dev and CISA KEV reachability without sending project information.
Show ok, information, warning or problem for each check, with a next action.
Missing cra.yml is information; unresolved runtime versions are coverage warnings.
Make no repairs or file changes. Exit 2 when any problem exists, otherwise 0.

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
fendkit doctor
```

## Examples

```
fendkit doctor
fendkit doctor --dir ./my-plugin --json
```

## Output

Shows text you can read in your terminal.

Use --json to get JSON for scripts and other programs.
