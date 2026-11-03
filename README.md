# template-go-action

A GitHub template repository for building Go-based GitHub Actions (Docker container actions) with automated CI/CD workflows.

<br/>

## What's Included

| Category | Files | Description |
|----------|-------|-------------|
| **Action** | `action.yml` | Action metadata with example inputs/outputs |
| **Docker** | `Dockerfile`, `.dockerignore` | Multi-stage build (golang:alpine → alpine) |
| **Go Code** | `cmd/`, `internal/` | Entry point, action logic, config loader, output helpers |
| **Build** | `Makefile` | build, test, cover, fmt, vet |
| **CI/CD** | `.github/workflows/` | CI (test + Docker + action test), release, changelog, contributors |
| **Config** | `.github/dependabot.yml` | Weekly dependency updates (Docker + Actions + Go modules) |
| **Docs** | `CLAUDE.md`, `docs/` | Project guidelines and development guide |

<br/>

## Quick Start

<br/>

### 1. Create from Template

Click **"Use this template"** on GitHub, or:

```bash
gh repo create my-action --template somaz94/template-go-action --public --clone
cd my-action
```

<br/>

### 2. Replace Placeholders

| Placeholder | Replace With | Example |
|-------------|-------------|---------|
| `YOUR_USERNAME` | Your GitHub username | `somaz94` |
| `YOUR_ACTION` | Your repository name | `my-awesome-action` |
| `YOUR_GITLAB_GROUP` | Your GitLab group (for mirror) | `backup6695808` |
| `myaction` | Your binary name | `my-awesome-action` |

Quick replace:

```bash
# macOS
find . -type f -not -path './.git/*' -exec sed -i '' \
  -e 's/YOUR_USERNAME/somaz94/g' \
  -e 's/YOUR_ACTION/my-awesome-action/g' \
  -e 's/YOUR_GITLAB_GROUP/backup6695808/g' \
  -e 's/myaction/my-awesome-action/g' {} +

# Linux
find . -type f -not -path './.git/*' -exec sed -i \
  -e 's/YOUR_USERNAME/somaz94/g' \
  -e 's/YOUR_ACTION/my-awesome-action/g' \
  -e 's/YOUR_GITLAB_GROUP/backup6695808/g' \
  -e 's/myaction/my-awesome-action/g' {} +
```

<br/>

### 3. Initialize Module

```bash
go mod init github.com/YOUR_USERNAME/YOUR_ACTION
go mod tidy
```

<br/>

### 4. Build & Test

```bash
make build    # → ./myaction
make test     # Run unit tests

# Docker test
docker build -t myaction:local .
docker run --rm -e INPUT_DRY_RUN=true myaction:local
```

<br/>

## Project Structure

```
.
├── cmd/
│   └── main.go                  # Entry point with signal handling
├── internal/
│   ├── action/
│   │   ├── action.go            # Core action logic (replace this)
│   │   └── action_test.go
│   ├── config/
│   │   ├── config.go            # Load INPUT_* env vars
│   │   └── config_test.go
│   └── output/
│       ├── output.go            # GitHub Actions output helpers
│       └── output_test.go
├── .github/
│   ├── workflows/
│   │   ├── ci.yml               # CI: test, Docker build, action test
│   │   ├── release.yml          # GitHub release + major tag update
│   │   ├── changelog-generator.yml
│   │   ├── contributors.yml
│   │   ├── dependabot-auto-merge.yml
│   │   ├── stale-issues.yml
│   │   ├── issue-greeting.yml
│   │   └── gitlab-mirror.yml
│   ├── dependabot.yml
│   └── release.yml              # Release note categories
├── scripts/
│   └── create-pr.sh             # Auto-generate PR body
├── action.yml                   # Action metadata (inputs/outputs)
├── Dockerfile                   # Multi-stage build
├── .dockerignore
├── .gitattributes
├── .gitignore
├── Makefile
├── CLAUDE.md
├── LICENSE
├── docs/
│   └── DEVELOPMENT.md
├── go.mod
└── README.md
```

<br/>

## How It Works

### Action Flow

```
GitHub Actions runner
  → Docker build (Dockerfile)
    → Reads INPUT_* env vars (internal/config)
    → Executes action logic (internal/action)
    → Writes GITHUB_OUTPUT (internal/output)
```

### Key Files to Modify

1. **`action.yml`** — Define your inputs, outputs, and branding
2. **`internal/config/config.go`** — Add fields for your inputs
3. **`internal/action/action.go`** — Replace with your action logic
4. **`Dockerfile`** — Add runtime dependencies (e.g., `git`, `curl`)

<br/>

## Makefile Targets

```bash
make help            # Show all targets
make build           # Build binary → ./myaction
make test            # Run unit tests with coverage
make cover           # Generate coverage report
make cover-html      # Open coverage in browser
make fmt             # Format code (gofmt)
make vet             # Run go vet
make branch name=x   # Create feature branch feat/x
make pr title="..."  # Test → push → create PR
make clean           # Remove build artifacts
```

<br/>

## CI/CD Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `ci.yml` | push (main), PR, dispatch | Unit tests → Docker build & dry-run → Action integration test |
| `release.yml` | tag push `v*` | GitHub release + major tag update (v1) |
| `changelog-generator.yml` | after release, PR merge | Auto-generate CHANGELOG.md |
| `contributors.yml` | after changelog | Auto-generate CONTRIBUTORS.md |
| `dependabot-auto-merge.yml` | dependabot PR | Auto-merge minor/patch updates |
| `stale-issues.yml` | daily cron | Auto-close stale issues (30d + 7d) |
| `issue-greeting.yml` | issue opened | Welcome message |
| `gitlab-mirror.yml` | push to main | Mirror to GitLab |

<br/>

### Workflow Chain

```
tag push v* → Create release + update major tag (v1)
                └→ Generate changelog
                      └→ Generate Contributors
```

<br/>

## GitHub Secrets Required

| Secret | Usage |
|--------|-------|
| `PAT_TOKEN` | Release, major tag update, contributors (cross-repo access) |
| `GITLAB_TOKEN` | GitLab mirror (optional) |

> `GITHUB_TOKEN` is automatically provided by GitHub Actions.

<br/>

## Release

```bash
git tag v1.0.0
git push origin v1.0.0
```

The release workflow automatically:
1. Creates a GitHub release with generated notes
2. Updates the major version tag (`v1` → points to `v1.0.0`)

Users reference your action as:

```yaml
- uses: YOUR_USERNAME/YOUR_ACTION@v1
```

<br/>

## Key Differences from CLI Template

| | `template-go-cli` | `template-go-action` |
|---|---|---|
| Entry point | Cobra CLI | `action.yml` + Docker |
| Distribution | GoReleaser + Homebrew | Docker container action |
| Config | CLI flags + YAML | `INPUT_*` env vars |
| Output | stdout/file | `GITHUB_OUTPUT` |
| Release | Multi-platform binaries | Major tag update (v1) |
| Makefile | build, branch, pr | build, test, branch, pr |

<br/>

## Conventions

- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `ci:`, `chore:`)
- **paths-ignore**: CI skips `.github/workflows/**` and `**/*.md` changes

<br/>

## License

See [LICENSE](LICENSE) — replace with your chosen license.
