.PHONY: help fmt vet test build install-hooks clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

fmt: ## Format Go code with gofmt
	@echo "Running gofmt..."
	@gofmt -w .
	@echo "Go code formatted."

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

build: ## Build the webhook binary
	@echo "Building webhook..."
	@go build -o webhook .

install-hooks: ## Install pre-commit hooks
	@echo "Installing pre-commit hooks..."
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "pre-commit hooks installed."; \
	else \
		echo "pre-commit not found. Git hooks are already set up manually."; \
		echo "To install pre-commit: pip install pre-commit"; \
	fi

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -f webhook
	@echo "Clean complete."

# Run all checks (formatting, vetting, testing)
check: fmt vet test ## Run all checks (fmt, vet, test)
	@echo "All checks passed!"