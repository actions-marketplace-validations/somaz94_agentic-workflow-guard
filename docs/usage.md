# Usage

<br/>

## Inputs

| Name | Default | Description |
|---|---|---|
| `path` | `.` | Repository root to scan |
| `fail_on` | `high` | Fail on a finding at or above this severity: `high`, `medium`, `low` or `none` |
| `sarif_file` | empty | Write SARIF 2.1.0 to this path |
| `ignore_rules` | empty | Comma-separated rule IDs to skip |

<br/>

## Outputs

| Name | Description |
|---|---|
| `findings` | Total number of findings |
| `high` | Number of high-severity findings |
| `medium` | Number of medium-severity findings |
| `low` | Number of low-severity findings |
| `warnings` | Number of warnings about files that could not be audited |
| `sarif_file` | Path of the SARIF file, empty when none was written |

<br/>

## What gets scanned

Files directly under `.github/workflows/` with a `.yml` or `.yaml` extension, except a `.lock.yml` next to the `.md` it was compiled from, plus these agent configs when present: `.claude/settings.json`, `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and `.gemini/settings.json`.

A reusable workflow or composite action referenced with `./` is read too, and a finding inside one is reported at that file and names its caller. References to another repository are not followed, because that would need the network.

A file that cannot be parsed becomes a warning, is listed in the job summary and is left out of the count of scanned files, and the scan continues. A symlink pointing outside `path` is not read.

The tree may come from a fork, so a scan has limits on file size, YAML alias expansion, call depth, followed calls, steps per job and time. No ordinary repository reaches them. Reaching one fails the step whatever `fail_on` says, because a partial scan must not read as a clean one.

<br/>

## Code scanning

Uploading needs `security-events: write`, and code scanning does not accept uploads from fork pull requests, so run this on `push`:

```yaml
name: Audit agent workflows
on:
  push:
    branches: [main]
    paths:
      - '.github/workflows/**'
      - '.claude/**'
      - '.mcp.json'

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: somaz94/agentic-workflow-guard@v1
        with:
          fail_on: none
          sarif_file: agentic-workflow-guard.sarif

      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: agentic-workflow-guard.sarif
```

<br/>

## Adopting on an existing repository

Start with `fail_on: none` to read the job summary without failing anything, then raise it once the findings are handled. Use `ignore_rules` for a rule you have decided does not apply; it applies to the whole repository.
