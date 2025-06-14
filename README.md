# OpenTelemetry Pod Mutation Webhook

A Kubernetes mutation webhook that automatically adds OpenTelemetry instrumentation annotations to pods for Python auto-instrumentation.

## Overview

This webhook automatically adds the following annotation to every pod created in the cluster:

```yaml
annotations:
  instrumentation.opentelemetry.io/inject-python: "opentelemetry-operator-system/instrumentation"
```

This enables automatic Python instrumentation via the OpenTelemetry Operator.

## Features

- Automatic injection of OpenTelemetry instrumentation annotations
- TLS certificate management via cert-manager
- Health checks and monitoring endpoints
- Security-hardened container image
- High availability with multiple replicas

## Prerequisites

- Kubernetes cluster
- cert-manager installed
- OpenTelemetry Operator installed

## Installation

1. Deploy the webhook:
   ```bash
   kubectl apply -k deploy/
   ```

2. The webhook will automatically start mutating pods with the OpenTelemetry annotation.

## Configuration

The webhook can be configured via environment variables:

- `TLS_CERT_FILE`: Path to TLS certificate file (default: `/etc/certs/tls.crt`)
- `TLS_KEY_FILE`: Path to TLS private key file (default: `/etc/certs/tls.key`)
- `WEBHOOK_PORT`: Port to listen on (default: `8443`)

## Development

### Code Formatting and Quality

This project uses pre-commit hooks to automatically format Go code with `gofmt` before each commit.

#### Setting up pre-commit hooks

The Git pre-commit hook is automatically installed when you clone the repository. You can also optionally use the `pre-commit` tool:

```bash
# Install pre-commit (optional)
pip install pre-commit
pre-commit install
```

#### Manual formatting

To format all Go files manually:

```bash
gofmt -w .
```

Or using the Makefile (if make is available):

```bash
make fmt          # Format code
make vet          # Run go vet
make test         # Run tests
make check        # Run all checks (fmt, vet, test)
```

### Building locally

```bash
go build -o webhook .
```

### Running tests

```bash
go test -v ./...
```

### Building Docker image

For local development:
```bash
docker build -t harbor.rackspace.koski.co/library/otel-pod-mutation:latest .
```

For Kubernetes environments (self-hosted runners), the CI/CD pipeline uses **Kaniko** running on **containerd** to build container images without needing a Docker daemon. The workflow pulls and runs Kaniko with the `native` snapshotter so it can operate in an unprivileged environment.

## GitHub Actions

The project includes a CI/CD pipeline that:

1. Runs tests and code quality checks
2. Builds and pushes Docker images to Harbor registry using Kaniko with containerd's `native` snapshotter (compatible with ARC Kubernetes runners)
3. Runs security scans with Trivy

Required secrets:
- `HARBOR_USERNAME`: Harbor registry username
- `HARBOR_PASSWORD`: Harbor registry password

## Security

- Runs as non-root user (65534)
- Read-only root filesystem
- Drops all capabilities
- Security scanning with Trivy

## License

[Add your license here]