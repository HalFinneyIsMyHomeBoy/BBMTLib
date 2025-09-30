# nodns-server Dockerfile
# ⚠️ WARNING: This container can modify certificate trust stores
# Only use in isolated testing environments!

FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the server
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-w -s" -o nodns-server .

# Production image with certificate management tools
FROM alpine:latest

# ⚠️ Install certificate management tools for DANGEROUS testing
RUN apk add --no-cache \
    ca-certificates \
    ca-certificates-bundle \
    openssl \
    curl \
    dig

# Create non-root user (though cert operations need root)
RUN adduser -D -s /bin/sh nodns

# Copy binary from builder
COPY --from=builder /app/nodns-server /usr/local/bin/nodns-server

# Copy example config
COPY --from=builder /app/config.yaml /etc/nodns-server/config.yaml

# Create directories for certificates and logs
RUN mkdir -p /var/log/nodns-server /usr/local/share/ca-certificates/nodns

# Set permissions
RUN chown -R nodns:nodns /var/log/nodns-server

# Expose DNS port
EXPOSE 5354/udp
EXPOSE 5354/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD dig @localhost -p 5354 health.check || exit 1

# Default to safe mode (certificates disabled)
USER root
ENTRYPOINT ["/usr/local/bin/nodns-server"]
CMD ["-port", "5354", "-cert-disable=true", "-verbose"]

# Labels for documentation
LABEL maintainer="no-dns project"
LABEL description="DNS server for .nostr domains with DANGEROUS certificate injection"
LABEL version="dev"
LABEL security.warning="This container can modify system certificate trust stores"
LABEL usage.safe="docker run -p 5354:5354/udp nodns-server"
LABEL usage.dangerous="docker run --privileged -p 5354:5354/udp nodns-server -cert-disable=false"