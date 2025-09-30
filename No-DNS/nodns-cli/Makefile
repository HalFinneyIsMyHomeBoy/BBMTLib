# nodns-cli Makefile for cross-platform builds

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X main.version=$(VERSION) -s -w"
BUILD_DIR = build
BINARY_NAME = nodns

# Go parameters
GOCMD = go
GOBUILD = $(GOCMD) build
GOCLEAN = $(GOCMD) clean
GOTEST = $(GOCMD) test
GOGET = $(GOCMD) get
GOMOD = $(GOCMD) mod

# Platforms to build for
PLATFORMS = \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64 \
	freebsd/amd64 \
	openbsd/amd64

.PHONY: all build clean test deps help install build-all $(PLATFORMS)

all: build

help:
	@echo "Available targets:"
	@echo "  build         - Build for current platform"
	@echo "  build-common  - Build for macOS and Linux (most common)"
	@echo "  build-all     - Build for all supported platforms"
	@echo "  deploy-ready  - Build Linux version for VPS deployment"
	@echo "  test          - Run tests"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Download dependencies"
	@echo "  install       - Install to GOPATH/bin"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Quick platform builds:"
	@echo "  linux         - Build Linux AMD64 binary"
	@echo "  mac           - Build macOS AMD64 binary"
	@echo "  windows       - Build Windows AMD64 binary"
	@echo "  arm64         - Build Linux ARM64 binary"

# Build for current platform
build:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Build for both macOS and Linux (most common deployment scenario)
build-common:
	@echo "Building for common platforms (macOS and Linux)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building for current platform..."
	@$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Building for Linux AMD64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux .
	@if [ "$$(go env GOOS)" = "darwin" ]; then \
		echo "Building for macOS AMD64..."; \
		GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .; \
		echo "Building for macOS ARM64..."; \
		GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .; \
	fi
	@echo "Common builds completed in $(BUILD_DIR)/"

# Build ready for VPS deployment
deploy-ready:
	@echo "Building deployment-ready binaries..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building current platform binary..."
	@$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Building Linux AMD64 for VPS deployment..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Creating deployment copy..."
	@cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BUILD_DIR)/nodns-linux
	@echo ""
	@echo "Deployment binaries ready:"
	@echo "  Local: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "  VPS:   $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"
	@echo "  Copy:  $(BUILD_DIR)/nodns-linux"

# Install to system
install:
	$(GOBUILD) $(LDFLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) .

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Run tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Build for all platforms
build-all: $(PLATFORMS)

# Template for building each platform
$(PLATFORMS):
	@echo "Building for $@..."
	@mkdir -p $(BUILD_DIR)/$@
	@GOOS=$(word 1,$(subst /, ,$@)) GOARCH=$(word 2,$(subst /, ,$@)) \
		$(GOBUILD) $(LDFLAGS) \
		-o $(BUILD_DIR)/$@/$(BINARY_NAME)$(if $(findstring windows,$@),.exe,) .
	@echo "Built: $(BUILD_DIR)/$@/$(BINARY_NAME)$(if $(findstring windows,$@),.exe,)"

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@for platform in $(PLATFORMS); do \
		echo "Packaging $$platform..."; \
		platform_dir="$(BUILD_DIR)/$$platform"; \
		archive_name="$(BINARY_NAME)-$(VERSION)-$$(echo $$platform | tr '/' '-')"; \
		if echo $$platform | grep -q windows; then \
			cd $$platform_dir && zip -q "$(CURDIR)/$(BUILD_DIR)/release/$$archive_name.zip" "$(BINARY_NAME).exe"; \
		else \
			cd $$platform_dir && tar -czf "$(CURDIR)/$(BUILD_DIR)/release/$$archive_name.tar.gz" "$(BINARY_NAME)"; \
		fi; \
	done
	@echo "Release archives created in $(BUILD_DIR)/release/"

# Development build with race detection
dev:
	$(GOBUILD) -race $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-dev .

# Static build (useful for containers)
static:
	CGO_ENABLED=0 $(GOBUILD) $(LDFLAGS) -a -installsuffix cgo -o $(BUILD_DIR)/$(BINARY_NAME)-static .

# Quick builds for common platforms
linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux .

mac:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-mac .

windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe .

# ARM builds
arm64:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 .

arm:
	GOOS=linux GOARCH=arm $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-arm .