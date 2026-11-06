# Development

<br/>

## Prerequisites

- Go, at the version in `go.mod`
- Docker, to build the image
- Make

<br/>

## Build and test

```bash
make build       # Build the binary
make test        # Unit tests with coverage
make cover       # Coverage report
make fmt         # Format
make vet         # go vet
```

To run the binary over a repository:

```bash
INPUT_PATH=testdata/risky INPUT_FAIL_ON=none ./agentic-workflow-guard
```

<br/>

## Layout

The package name is the role: `expr` parses expressions, `reach` evaluates an `if:` for one actor and event, `workflow` loads a file with line numbers, `registry` holds the agent catalog, `audit` applies the rules, `report` renders the output.

<br/>

## Adding or updating an agent

Edit [`internal/registry/agents.yaml`](../internal/registry/agents.yaml). Agents, their risky inputs, attacker-written fields and exec-equivalent commands all live there, so a renamed input or a new agent is normally a data change. Add a case to `internal/audit/audit_test.go`.

Read the agent action's own `action.yml` before setting `actor_check`: it records whether the action refuses actors without write access, and getting it wrong in either direction misstates every finding for that agent.

A command-line agent has a `run_pattern` instead of `uses`, and its inputs read the script as `run`. Set `power` from what the tool's documentation says it does unattended, since the default differs between tools.

<br/>

## Fixtures

`testdata/clean`, `testdata/risky` and `testdata/indirect` are synthetic workflows that back the CI jobs. `TestFixtures` in `cmd/main_test.go` pins what they produce, and `ci.yml` and `use-action.yml` assert the same counts, so update them together. Never copy a real repository's workflow into a fixture: a finding here would publish that repository's exposure.

The screenshot in the README, `docs/images/annotations.png`, is the Annotations panel of a `ci.yml` run on `main`, so every finding in it comes from these fixtures. When a rule's message changes, replace it with the same panel from a newer run.

<br/>

## Release

Releases run through the shared workflow in `somaz94/.github`. `action.yml` pins the published image, so a version's image must exist before its tag does: publish it with `release.yml` through `workflow_dispatch`, move the pin, then push the tag.
