# Build stage
# Pinned to the BUILD platform, not the target: the image is published
# multi-arch, and letting the toolchain stage run under QEMU emulation to
# produce an arm64 binary is minutes of emulated compilation for no reason. Go
# cross-compiles natively instead, driven by the TARGET* args buildx injects.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

WORKDIR /build

# BuildKit sets both for the target platform, the host's for a plain
# `docker build` without --platform; the TARGETOS default just restates linux.
#
# BuildKit is required either way — `$BUILDPLATFORM` on the FROM above is a
# BuildKit-only variable, and the legacy builder fails to parse the line rather
# than ignoring it. That is the default builder since Docker 23, so this only
# bites an explicit DOCKER_BUILDKIT=0.
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev

# Copy module manifests first to leverage Docker layer cache for `go mod download`.

COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -X github.com/somaz94/agentic-workflow-guard/internal/action.Version=${VERSION}" \
      -o /agentic-workflow-guard ./cmd/main.go

# Runtime stage
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.source="https://github.com/somaz94/agentic-workflow-guard" \
      org.opencontainers.image.description="Audit GitHub Actions workflows that run AI agents for prompt-injection exposure" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --from=builder /agentic-workflow-guard /usr/local/bin/agentic-workflow-guard

# Runs as root: GitHub Actions bind-mounts $GITHUB_WORKSPACE with the runner uid,
# and writing the SARIF file back to that mount needs write access.
ENTRYPOINT ["agentic-workflow-guard"]
