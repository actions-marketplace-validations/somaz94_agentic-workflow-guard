# CLAUDE.md — YOUR_ACTION

A Go-based GitHub Action (Docker container action).

## Build & Test

```bash
make build       # Build binary
make test        # Unit tests with coverage
make cover       # Generate coverage report
make fmt         # Format code
make vet         # Run go vet
```

## Project Structure

```
cmd/main.go                  # Entry point
internal/
  action/
    action.go                # Core action logic
    action_test.go
  config/
    config.go                # Load INPUT_* env vars
    config_test.go
  output/
    output.go                # GitHub Actions output helpers
    output_test.go
action.yml                   # Action metadata (inputs/outputs)
Dockerfile                   # Multi-stage build (golang:alpine → alpine)
```

## Key Concepts

- **action.yml**: Defines inputs, outputs, and Docker entrypoint
- **config**: Reads `INPUT_*` environment variables set by GitHub Actions
- **output**: Writes to `GITHUB_OUTPUT` file for action outputs
- **Dockerfile**: Multi-stage build for minimal runtime image

## CI

- `ci.yml` — Unit tests, Docker build & dry-run, action integration test
- Docker: multi-stage build (golang:1.26-alpine → alpine:3.23)
