# CLAUDE.md

<br/>

## Project Structure

- Go-based GitHub Action (Docker container action) that audits workflows running AI agents for prompt-injection exposure
- Read-only by design: no token, no API key and no network, so it can run on fork pull requests. Keep it that way
- Reads `.github/workflows/*.{yml,yaml}` and committed agent configs; see `docs/usage.md`

<br/>

## Build & Test

```bash
make build       # Build binary
make test        # Unit tests with coverage
make cover       # Coverage report
make fmt         # Format code
make vet         # Run go vet
```

<br/>

## Key Concepts

- **`internal/reach` is the core.** It evaluates `if:` per event against an actor model instead of matching text. A regex passed one-branch gates and missed the most serious sample in the measurement that shaped this tool (decided 2026-11-03)
- **`internal/registry/agents.yaml` is data.** A new agent or a renamed input goes there, not in code. `actor_check` must come from the agent action's own `action.yml`
- **A wrong `Indeterminate` hides findings.** Only an output that can carry an authorization result lowers severity (`gate_output_pattern`, or a producer that authorizes). Treating every output as a gate pushed a full-access agent down to medium in the measurement
- **Write permissions only raise severity.** They appear on nearly every agent workflow, so they are never a finding alone
- **LLM output interpolated into `run:` is out of scope** because zizmor's `template-injection` already reports it. Do not add a rule that duplicates a general linter

<br/>

## Fixtures

`testdata/` is synthetic. Never copy a real repository's workflow into it, name a real repository in a doc, or commit a real or realistic credential; `internal/audit/config_test.go` builds its fake at run time so the tree holds nothing shaped like one.

<br/>

## CI

- `ci.yml` — Unit tests with a coverage threshold, Docker build, then fixture jobs through `uses: ./`, including a scan of this repository
- `use-action.yml` — The same fixtures through the released `@v1`
- Release, changelog and community workflows follow the other Docker action repositories and call `somaz94/.github`
