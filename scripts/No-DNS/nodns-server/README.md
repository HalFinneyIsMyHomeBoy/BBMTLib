# nodns-server

A DNS server implementation that resolves `.nostr` domains using Nostr events.

## ⚠️ 🚨 CRITICAL SECURITY WARNING 🚨 ⚠️

**THIS IS AN EXPERIMENTAL IMPLEMENTATION WITH AUTOMATIC CERTIFICATE INSTALLATION**

### EXTREME DANGER - USE WITH CAUTION

This server can **AUTOMATICALLY MODIFY YOUR SYSTEM'S CERTIFICATE TRUST STORE** without explicit user consent on each certificate. This functionality is **EXTREMELY DANGEROUS** and can:

- ✅ **COMPROMISE YOUR SYSTEM SECURITY**
- ✅ **ALLOW MALICIOUS ACTORS TO INTERCEPT YOUR ENCRYPTED TRAFFIC**  
- ✅ **BREAK TLS/SSL SECURITY FOR YOUR ENTIRE SYSTEM**
- ✅ **ENABLE MAN-IN-THE-MIDDLE ATTACKS**
- ✅ **BYPASS BROWSER SECURITY WARNINGS**

### What This Means

When this server fetches certificates from Nostr events, it can:
1. Add arbitrary certificates to your system's trusted certificate store
2. Make your system trust certificates signed by unknown/untrusted entities
3. Override security protections in browsers and applications
4. Create security vulnerabilities system-wide

### Before You Run This Software

**ONLY USE THIS SOFTWARE IF:**
- ✅ You are a developer testing in an isolated environment
- ✅ You understand the security implications fully
- ✅ You are prepared to manually audit every certificate
- ✅ You can restore your system if compromised
- ✅ You are NOT running this on production systems
- ✅ You are NOT running this on systems with sensitive data

**NEVER USE THIS SOFTWARE IF:**
- ❌ You don't fully understand certificate authorities and PKI
- ❌ You're running this on a production system
- ❌ You have sensitive data on the system
- ❌ You're not prepared to deal with security compromises
- ❌ You can't verify the integrity of certificates yourself

### Recommended Safety Measures

1. **Run in isolated VMs only**
2. **Never use on your primary workstation**
3. **Monitor certificate installations carefully**
4. **Have a system restore plan ready**
5. **Disable auto-certificate installation by default**
6. **Manually review each certificate before installation**

---

## Features

- DNS resolution for `.nostr` domains using Nostr kind 11111 events
- Support for multiple DNS record types (A, AAAA, CNAME, TXT, MX, SRV, etc.)
- **[DANGEROUS]** Automatic certificate fetching from Nostr kind 30003 events
- **[DANGEROUS]** Cross-platform trust store integration
- Forwarding of non-nostr domains to upstream DNS servers

## Installation

⚠️ **READ THE SECURITY WARNING ABOVE FIRST** ⚠️

```bash
# Clone repository
git clone https://github.com/your-org/nostr-dns
cd nostr-dns/nodns-server

# Build
go build -o nodns-server

# Run (DANGEROUS - see warnings above)
sudo ./nodns-server
```

## Configuration

```yaml
# config.yaml
port: 5354
relays:
  - "wss://relay.damus.io"
  - "wss://nos.lol"
  - "wss://relay.snort.social"
forward_dns:
  - "1.1.1.1"
  - "1.0.0.1"
ttl: 3600

# Certificate settings (DANGEROUS)
certificates:
  auto_install: false    # KEEP THIS FALSE FOR SAFETY
  prompt_user: true      # KEEP THIS TRUE FOR SAFETY
  skip_expired: true
  skip_self_signed: false  # Self-signed certs can be dangerous too
```

## Usage

### Safe Mode (Recommended)
```bash
# Run with certificate installation disabled
./nodns-server -cert-auto-install=false -cert-prompt=true
```

### Dangerous Mode (Experts Only)
```bash
# ⚠️ DANGER: Auto-installs certificates without prompting
./nodns-server -cert-auto-install=true
```

### Testing DNS Resolution
```bash
# Query DNS records
dig @localhost -p 5354 npub1abc.nostr A

# Test certificate fetching (will prompt for installation)
dig @localhost -p 5354 npub1secure.nostr A
```

## How It Works

1. **DNS Query**: Client queries for `npub1abc.nostr`
2. **Pubkey Extraction**: Extract pubkey from npub
3. **Nostr Query**: Fetch both kind 11111 (DNS records) and kind 30003 (certificates) events
4. **DNS Response**: Generate DNS response from record tags
5. **Certificate Installation**: **[DANGEROUS]** Automatically install found certificates

## Event Formats

### DNS Records (kind 11111)
```json
{
  "kind": 11111,
  "content": "",
  "tags": [
    ["record", "A", "@", "1.2.3.4", "", "", "", "", "", "", "3600"]
  ]
}
```

### Certificates (kind 30003) - ⚠️ DANGEROUS ⚠️
```json
{
  "kind": 30003,
  "content": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "tags": [
    ["d", "nostr"],
    ["expiry", "1735689600"]
  ]
}
```

## Security Considerations

### Certificate Validation
This software attempts to validate certificates, but validation can be bypassed or may contain bugs. **Never rely solely on automated validation.**

### Trust Store Modifications
Modifying system trust stores is a **privileged operation** that can compromise system security. This software requires administrative privileges and can make system-wide security changes.

### Nostr Event Authenticity
While Nostr events are cryptographically signed, this doesn't guarantee the certificates contained within them are trustworthy or legitimate.

## Platform Support

- ✅ macOS (requires admin privileges)
- ✅ Linux (requires sudo)  
- ✅ Windows (requires administrator privileges)

## Development

### Build Requirements
- Go 1.21+
- Administrative privileges for certificate operations

### Testing
```bash
# Unit tests
go test ./...

# Integration tests (DANGEROUS - modifies trust store)
go test -tags=integration ./...
```

## Troubleshooting

### Certificate Installation Fails
- Check if running with appropriate privileges
- Verify certificate format and validity
- Check system trust store accessibility

### DNS Resolution Issues
- Verify relay connectivity
- Check event format compliance
- Monitor relay response times

## Contributing

**Please be extremely careful when contributing to certificate-related code.** Security vulnerabilities in this area can compromise entire systems.

1. All certificate-related PRs require thorough security review
2. Test only in isolated environments
3. Document security implications of changes
4. Consider the principle of least privilege

## License

MIT License - **Use at your own risk**

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 

**THE AUTHORS ARE NOT RESPONSIBLE FOR ANY SECURITY COMPROMISES, DATA LOSS, OR SYSTEM DAMAGE RESULTING FROM THE USE OF THIS SOFTWARE.**

This software modifies critical system security infrastructure. Use only if you fully understand the risks and accept full responsibility for any consequences.

---

## ⚠️ FINAL WARNING ⚠️

**This software can compromise your system's security by automatically installing untrusted certificates. Only use in isolated testing environments. The authors strongly recommend against using this software on any system containing sensitive data or connected to production networks.**