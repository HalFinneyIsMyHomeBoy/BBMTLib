# nodns-cli

A command-line tool for managing decentralized DNS records and SSL certificates using the Nostr protocol.

## Features

### 🔐 Authentication
- **Generate new key**: Create a new Nostr key pair
- **Login with nsec**: Import existing private key (hex or bech32)
- **Amber integration**: Login via QR code (coming soon)
- **Bunker support**: NIP-46 remote signing (coming soon)

### 📋 DNS Records Management
- **Easy helpers** for common record types (A, CNAME, TXT)
- **Full support** for all DNS record types (MX, SRV, SOA, CAA, DNSKEY, etc.)
- **Local management** with publish-when-ready workflow
- **Automatic validation** of record data

### 🔐 Certificate Management
- **Import certificates** from files or paste PEM data
- **Generate self-signed certificates** for any TLD
- **Multi-TLD support** (.nostr, .net, .com, etc.)
- **Certificate validation** and expiry tracking
- **Automatic publishing** to Nostr with addressable events

## Installation

### Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/nostr-dns/nodns-cli/releases).

### Build from Source

```bash
git clone https://github.com/nostr-dns/nodns-cli
cd nodns-cli
make build
```

### Docker

```bash
docker pull nostr-dns/nodns-cli:latest
docker run -it --rm -v ~/.nodns-cli:/home/nodns/.nodns-cli nostr-dns/nodns-cli
```

## Quick Start

### 1. Login or Generate Key

```bash
# Generate a new key pair
nodns-cli login generate

# Or login with existing nsec
nodns-cli login nsec nsec1your_private_key_here
```

### 2. Add DNS Records

```bash
# Add an A record for your domain
nodns-cli records add a @ 1.2.3.4

# Add a CNAME for www subdomain
nodns-cli records add cname www example.com

# Add a TXT record
nodns-cli records add txt @ "v=spf1 include:_spf.google.com ~all"
```

### 3. Generate SSL Certificates

```bash
# Generate a self-signed certificate for .nostr
nodns-cli certs generate nostr

# Or generate for multiple TLDs
nodns-cli certs generate # Interactive selection
```

### 4. Publish to Nostr

```bash
# Publish DNS records
nodns-cli records publish

# Publish certificates
nodns-cli certs publish
```

## Usage

### Interactive Mode

Run the CLI without any arguments to enter interactive mode with a menu-driven interface:

```bash
nodns
```

This provides:
- 🔐 Login / Authentication management
- 📡 DNS Records Management (list, add, remove with live Nostr sync)
- 🔒 Certificate Management (generate, list, add, remove with automatic publishing)
- ℹ️ Status display showing login state and configuration
- ❌ Exit option

### Non-Interactive Mode

All commands support direct execution with command-line arguments for automation and scripting:

#### Authentication Commands

```bash
# Interactive login menu
nodns login

# Generate new key pair
nodns login generate

# Login with nsec (prompted securely)
nodns login nsec

# Login with nsec directly
nodns login nsec nsec1your_key_here

# Check login status
nodns login status

# Logout
nodns login logout
```

#### DNS Records Commands

```bash
# Interactive records menu
nodns records

# List current records from Nostr
nodns records list

# Add records with TTL flags (non-interactive)
nodns records add a @ 192.168.1.1 --ttl 7200
nodns records add a www 192.168.1.2 --ttl 3600
nodns records add cname blog example.com --ttl 3600
nodns records add txt @ "v=spf1 ~all" --ttl 1800
nodns records add txt _dmarc "v=DMARC1; p=none" --ttl 3600

# Add records (interactive mode - will prompt for values)
nodns records add

# Remove a record (interactive selection)
nodns records remove
```

#### Certificate Commands

```bash
# Interactive certificate menu
nodns certs

# List certificates from Nostr
nodns certs list

# Generate certificates with output directory (non-interactive)
nodns certs generate nostr --output ./certs
nodns certs generate nostr net com --output /path/to/certs

# Generate certificate (interactive TLD selection)
nodns certs generate

# Add certificate from file
nodns certs add nostr /path/to/cert.pem

# Add certificate interactively (paste PEM)
nodns certs add nostr

# Remove certificate (interactive selection)
nodns certs remove
```

### Command Examples by Use Case

#### Setting up a new domain

```bash
# 1. Login or generate new key
nodns login generate

# 2. Add basic DNS records
nodns records add a @ 192.168.1.1 --ttl 7200
nodns records add cname www example.com --ttl 3600
nodns records add txt @ "v=spf1 include:_spf.google.com ~all" --ttl 1800

# 3. Generate SSL certificate
nodns certs generate nostr --output ./ssl-certs

# 4. Verify everything is published
nodns records list
nodns certs list
```

#### Automation/CI Integration

```bash
#!/bin/bash
# Deploy script example

# Login with environment variable
nodns login nsec $NOSTR_PRIVATE_KEY

# Update A record for production deployment
nodns records add a @ $NEW_SERVER_IP --ttl 300

# Generate fresh certificate if needed
nodns certs generate nostr net --output /etc/ssl/certs

# Verify deployment
nodns records list | grep "A.*@"
```

#### Development workflow

```bash
# Quick interactive setup
nodns

# Or direct commands for specific tasks
nodns records add a staging $STAGING_IP --ttl 60
nodns certs generate nostr --output ./dev-certs
```

## Configuration

Configuration is stored in `~/.nodns-cli.yaml`:

```yaml
relays:
  - wss://relay.damus.io
  - wss://nos.lol
  - wss://relay.snort.social
```

You can also set relays via command line:
```bash
nodns-cli --relays wss://relay1.com,wss://relay2.com records publish
```

## Your Nostr Domain

After logging in, your domain will be available at:
```
{your-npub}.nostr
```

For example: `npub1abc123...xyz.nostr`

## DNS Record Types Supported

### Basic Records
- **A**: IPv4 addresses
- **AAAA**: IPv6 addresses
- **CNAME**: Canonical names
- **TXT**: Text records
- **NS**: Name servers
- **PTR**: Reverse DNS

### Mail Records
- **MX**: Mail exchange servers

### Service Records
- **SRV**: Service location records

### Security Records
- **CAA**: Certificate Authority Authorization
- **DNSKEY**: DNS public keys
- **DS**: Delegation Signer
- **TLSA**: Transport Layer Security Authentication

### Administrative Records
- **SOA**: Start of Authority

## Certificate Management

### Supported TLDs
- `.nostr` (primary)
- `.net`
- `.com`
- `.org`
- `.io`
- `.dev`
- Custom TLDs

### Certificate Sources
- **Import existing**: Paste PEM or load from file
- **Generate new**: Self-signed certificates with proper Subject Alternative Names
- **Multi-domain**: Generate certificates for multiple TLDs simultaneously

### Certificate Features
- Automatic validation and parsing
- Expiry tracking and warnings
- Addressable Nostr events (one per TLD)
- Private key storage for generated certificates

## Building

### Prerequisites
- Go 1.21 or later
- Make (optional)

### Build Commands

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Create release archives
make release

# Build for specific platforms
make linux
make mac
make windows
make arm64

# Development build with race detection
make dev

# Static build (for containers)
make static

# Run tests
make test

# Clean build artifacts
make clean
```

### Docker Build

```bash
# Build Docker image
docker build -t nodns-cli .

# Run with volume for config persistence
docker run -it --rm -v ~/.nodns-cli:/home/nodns/.nodns-cli nodns-cli
```

## File Locations

- **Config**: `~/.nodns-cli.yaml`
- **Auth**: `~/.nodns-cli-auth`
- **Records**: `~/.nodns-cli-records`
- **Certificates**: `~/.nodns-cli-certs`
- **Generated Keys**: `/tmp/nodns-{npub}-{tld}.key`

## Protocol Specifications

This tool implements:
- **DNS Record Events**: NIP-XX (kind 11111) - Fixed position DNS record encoding
- **Certificate Events**: NIP-XX (kind 30003) - Addressable certificate events

## Security Considerations

- Private keys are stored encrypted locally
- Certificates are validated before use
- All Nostr events are cryptographically signed
- Generated private keys for certificates are saved securely

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/nostr-dns/nodns-cli/issues)
- **Documentation**: [Protocol Specs](../docs/)
- **Nostr**: Search for `#nostrdns` on your favorite Nostr client

## Related Projects

- [Nostr DNS Server](../nodns-old/) - TypeScript DNS server implementation
- [Protocol Documentation](../docs/) - Detailed protocol specifications