# Multi-stage build for nodns-cli
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'container')" \
    -a -installsuffix cgo \
    -o nodns-cli .

# Final stage - minimal runtime image
FROM alpine:3.18

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -g 1001 nodns && \
    adduser -D -s /bin/sh -u 1001 -G nodns nodns

# Copy binary from builder stage
COPY --from=builder /app/nodns-cli /usr/local/bin/nodns-cli

# Set proper permissions
RUN chmod +x /usr/local/bin/nodns-cli

# Switch to non-root user
USER nodns

# Set working directory
WORKDIR /home/nodns

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nodns-cli login status || exit 1

# Default command
ENTRYPOINT ["nodns-cli"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="nodns-cli" \
      org.opencontainers.image.description="Command-line tool for managing Nostr DNS records and certificates" \
      org.opencontainers.image.vendor="Nostr DNS" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/nostr-dns/nodns-cli"