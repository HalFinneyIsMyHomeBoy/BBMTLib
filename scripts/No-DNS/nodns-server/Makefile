# nodns-server Makefile

# Build variables
BINARY_NAME=nodns-server
VERSION ?= dev
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
COMMIT_HASH=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go variables
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# Build flags
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.CommitHash=$(COMMIT_HASH)"

.PHONY: help build clean test install deps run dev docker

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@egrep '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

deps: ## Download dependencies
	go mod download
	go mod tidy

build: deps ## Build the binary
	@echo "Building $(BINARY_NAME) for $(GOOS)/$(GOARCH)..."
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o build/$(BINARY_NAME) .
	@echo "Built: build/$(BINARY_NAME)"

build-all: deps ## Build for all platforms
	@echo "Building for multiple platforms..."
	@mkdir -p build
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o build/$(BINARY_NAME)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o build/$(BINARY_NAME)-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o build/$(BINARY_NAME)-darwin-amd64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o build/$(BINARY_NAME)-darwin-arm64 .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o build/$(BINARY_NAME)-windows-amd64.exe .
	@echo "Built all platform binaries in build/"

install: build ## Install the binary to GOPATH/bin
	go install $(LDFLAGS) .

clean: ## Clean build artifacts
	rm -rf build/
	go clean

test: ## Run tests
	go test -v ./...

test-race: ## Run tests with race detection
	go test -race -v ./...

test-coverage: ## Run tests with coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

run: build ## Run the server (requires sudo for port 53)
	@echo "⚠️  WARNING: This will run with certificate functionality DISABLED by default"
	@echo "⚠️  Use -cert-disable=false to enable dangerous certificate features"
	sudo ./build/$(BINARY_NAME) -cert-disable=true

run-dev: build ## Run in development mode on port 5354
	@echo "Running in development mode on port 5354..."
	@echo "⚠️  Certificate functionality DISABLED for safety"
	./build/$(BINARY_NAME) -port 5354 -cert-disable=true -verbose

run-unsafe: build ## ⚠️ DANGER: Run with certificate auto-install enabled
	@echo "🚨🚨🚨 DANGER: Running with certificate auto-install enabled 🚨🚨🚨"
	@echo "This can compromise your system security!"
	@read -p "Type 'I UNDERSTAND THE RISKS' to continue: " confirm; \
	if [ "$$confirm" = "I UNDERSTAND THE RISKS" ]; then \
		sudo ./build/$(BINARY_NAME) -cert-auto-install=true; \
	else \
		echo "Aborting for safety."; \
	fi

config: ## Generate example configuration file
	@echo "Generating example config.yaml..."
	@echo "# nodns-server configuration" > config.yaml
	@echo "# ⚠️ SECURITY WARNING: Certificate features can be extremely dangerous" >> config.yaml
	@echo "" >> config.yaml
	@echo "# DNS server port (requires root/admin for port 53)" >> config.yaml
	@echo "port: 5354" >> config.yaml
	@echo "" >> config.yaml
	@echo "# Nostr relays to query for DNS records and certificates" >> config.yaml
	@echo "relays:" >> config.yaml
	@echo "  - \"wss://relay.damus.io\"" >> config.yaml
	@echo "  - \"wss://nos.lol\"" >> config.yaml
	@echo "  - \"wss://relay.snort.social\"" >> config.yaml
	@echo "  - \"wss://relay.nostr.band\"" >> config.yaml
	@echo "  - \"wss://nostr.wine\"" >> config.yaml
	@echo "" >> config.yaml
	@echo "# Forward DNS servers for non-.nostr domains" >> config.yaml
	@echo "forward_dns:" >> config.yaml
	@echo "  - \"1.1.1.1\"  # Cloudflare" >> config.yaml
	@echo "  - \"1.0.0.1\"  # Cloudflare" >> config.yaml
	@echo "" >> config.yaml
	@echo "# Default TTL for DNS responses (seconds)" >> config.yaml
	@echo "ttl: 3600" >> config.yaml
	@echo "" >> config.yaml
	@echo "# Certificate settings - ⚠️ EXTREMELY DANGEROUS ⚠️" >> config.yaml
	@echo "certificates:" >> config.yaml
	@echo "  # NEVER enable auto_install in production!" >> config.yaml
	@echo "  auto_install: false" >> config.yaml
	@echo "  # Always prompt users before installing certificates" >> config.yaml
	@echo "  prompt_user: true" >> config.yaml
	@echo "  # Only install certificates for these TLDs (empty = all TLDs)" >> config.yaml
	@echo "  required_tlds: []" >> config.yaml
	@echo "  # Skip expired certificates" >> config.yaml
	@echo "  skip_expired: true" >> config.yaml
	@echo "  # Skip self-signed certificates (recommended for security)" >> config.yaml
	@echo "  skip_self_signed: true" >> config.yaml
	@echo "  # Skip certificates older than this many days" >> config.yaml
	@echo "  max_age_days: 365" >> config.yaml
	@echo "  # Path to certificate audit log file" >> config.yaml
	@echo "  audit_log: \"\"" >> config.yaml
	@echo "  # RECOMMENDED: Completely disable certificate functionality" >> config.yaml
	@echo "  disable_dangerous: true" >> config.yaml
	@echo "" >> config.yaml
	@echo "# Logging configuration" >> config.yaml
	@echo "logging:" >> config.yaml
	@echo "  level: \"info\"     # debug, info, warn, error" >> config.yaml
	@echo "  format: \"text\"    # text, json" >> config.yaml
	@echo "  audit_log: \"\"     # Path to audit log file" >> config.yaml
	@echo "Created config.yaml with safe defaults"

docker: ## Build Docker image
	docker build -t nodns-server:$(VERSION) .

docker-run: ## Run in Docker (safe mode)
	docker run -p 5354:5354 nodns-server:$(VERSION) -port 5354 -cert-disable=true

# Development helpers
fmt: ## Format code
	go fmt ./...

lint: ## Run linter
	golangci-lint run

vet: ## Run go vet
	go vet ./...

mod-update: ## Update Go modules
	go get -u ./...
	go mod tidy

# Security helpers
security-scan: ## Run security scan
	gosec ./...

check-deps: ## Check for vulnerable dependencies  
	govulncheck ./...

# Example usage
example: run-dev ## Run example server

# Help for dangerous operations
danger-help: ## Show help for dangerous certificate operations
	@echo "🚨 DANGEROUS CERTIFICATE OPERATIONS 🚨"
	@echo ""
	@echo "The following operations can compromise system security:"
	@echo ""
	@echo "  make run-unsafe    - Run with auto-certificate installation"
	@echo ""  
	@echo "⚠️  These should ONLY be used in isolated testing environments!"
	@echo "⚠️  Never use on production systems or systems with sensitive data!"
	@echo "⚠️  Understand PKI/certificate security before proceeding!"
	@echo ""
	@echo "Safer alternatives:"
	@echo "  make run-dev       - Development mode (port 5354, certs disabled)"
	@echo "  make run           - Production mode (certs disabled)"

.DEFAULT_GOAL := help