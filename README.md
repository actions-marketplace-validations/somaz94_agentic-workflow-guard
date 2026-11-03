# Agentic Workflow Guard

[![Continuous Integration](https://github.com/somaz94/agentic-workflow-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/somaz94/agentic-workflow-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Latest Tag](https://img.shields.io/github/v/tag/somaz94/agentic-workflow-guard)](https://github.com/somaz94/agentic-workflow-guard/tags)

A GitHub Action that audits workflows running AI agents for prompt-injection exposure: who can start the agent, what text they can feed it, and what it can do afterwards.

It reads files only. It needs no token, no API key and no network, so it runs on pull requests from forks.

<br/>

## Why

An issue title or a pull request body is text an outsider writes. When a workflow hands that text to an agent holding tools and a token, the outsider is giving the agent instructions. The usual template-injection advice does not help, because the model reads the content rather than the shell.

General workflow linters flag the trigger. This action answers the question that follows: can this particular agent, with these inputs, be reached and driven by someone without write access?

<br/>

## Quick Start

```yaml
name: Audit agent workflows
on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - '.claude/**'
      - '.mcp.json'

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: somaz94/agentic-workflow-guard@v1
```

To see findings in the Security tab, write SARIF and upload it. See [docs/usage.md](docs/usage.md).

<br/>

## What it checks

| Rule | Finding |
|---|---|
| `open-invocation` | An outsider can start the agent |
| `untrusted-input` | Attacker-written text flows into the agent's input |
| `untrusted-checkout` | The agent runs after checking out untrusted code |
| `broad-tools` | The agent can run arbitrary commands |
| `full-output` | Full agent output goes to the job log |
| `agent-settings` | A committed agent config relaxes permissions |
| `mcp-secret` | A credential is committed in an MCP config |
| `mcp-unpinned` | An MCP server runs an unpinned package |

[docs/rules.md](docs/rules.md) explains each rule, how severity is decided, and what to change. The supported agents are listed in [`internal/registry/agents.yaml`](internal/registry/agents.yaml).

<br/>

## How it decides

Three things separate this from a text search:

- **`if:` is evaluated, event by event.** A gate on one `||` branch says nothing about the others. `github.event_name == 'issues' || github.event.comment.author_association == 'OWNER'` lets anyone in by opening an issue, and it is reported.
- **Each agent's own actor check counts.** An agent action that refuses actors without write access stays protected until its allowlist says `*`, so a weak `if:` in front of it is not a finding.
- **Severity follows what the agent can do.** Text reaching a model with no tools is not the same as text reaching one with `Bash(find:*)`, which runs any program through `-exec`.

A gate the workflow only enforces at run time, such as an authorization job whose output decides the next one, cannot be proven from the file. Those findings drop one severity level and ask you to verify the gate.

<br/>

## Limitations

This is static analysis, and a clean result is not a proof of safety.

- Agents started from a `run:` step, and compiled GitHub Agentic Workflows, are not detected
- A called reusable workflow is not followed into its file
- Text is traced one step back, through a step's output or a file it writes. Longer chains are not followed
- `pull_request` and its review events are out of scope: a fork gets no secrets and a read-only token there

<br/>

## Documentation

- [Usage](docs/usage.md): inputs, outputs and SARIF upload
- [Rules](docs/rules.md): each rule and how severity is decided
- [Development](docs/DEVELOPMENT.md): building, testing and adding an agent

<br/>

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
