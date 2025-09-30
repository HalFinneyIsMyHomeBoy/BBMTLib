# DNS Resolution Process - Go Implementation

## Overview

This document outlines the DNS resolution process for the new Go-based `nodns-server`, adapting from the old TypeScript implementation to use the updated DNS Record Events spec and adding certificate fetching/trust store integration.

## Architecture Comparison

### Old Implementation (TypeScript)
- Used kind 11111 "transport method announcement events"
- Parsed flexible transport method tags: `["clearnet", "192.168.1.100", "http"]`
- Only supported IP address resolution
- No certificate handling

### New Implementation (Go)
- Uses kind 11111 "DNS Record Events" with structured `record` tags
- Supports full DNS record types (A, AAAA, CNAME, TXT, MX, SRV, etc.)
- Integrates certificate fetching from kind 30003 events
- Cross-platform certificate trust store integration

## DNS Resolution Flow

```
DNS Query: npub1abc.nostr (A record)
    ↓
1. Parse domain → extract npub → convert to pubkey
    ↓
2. Query Nostr relays for kind 11111 by pubkey
    ↓
3. Parse record tags, filter by DNS type and name
    ↓
4. If certificate records found, fetch kind 30003 for TLD
    ↓
5. Validate and install certificate to trust store
    ↓
6. Generate DNS response with proper records and TTL
    ↓
7. Send DNS response
```

## Go Package Structure

```
nodns-server/
├── main.go                    # Server entry point
├── internal/
│   ├── dns/
│   │   ├── server.go         # DNS server implementation
│   │   ├── resolver.go       # DNS resolution logic
│   │   └── response.go       # DNS response generation
│   ├── nostr/
│   │   ├── client.go         # Nostr relay client
│   │   ├── events.go         # Event parsing/validation
│   │   └── records.go        # DNS record parsing from tags
│   ├── certs/
│   │   ├── fetcher.go        # Certificate fetching from Nostr
│   │   ├── validator.go      # Certificate validation
│   │   └── truststore.go     # Cross-platform trust store
│   └── config/
│       └── config.go         # Server configuration
└── docs/
    ├── dns_resolution_process.md
    └── cert_fetching.md
```

## Key Components

### 1. DNS Record Parsing

#### Record Tag Format (11 elements)
```go
type DNSRecord struct {
    Type     string    // A, AAAA, CNAME, TXT, MX, SRV, etc.
    Name     string    // "@" for root, subdomain name, or FQDN
    Data     []string  // pos1-pos7 data fields
    TTL      uint32    // TTL in seconds (default 3600)
}

// Parse record tag: ["record", "A", "@", "1.2.3.4", "", "", "", "", "", "", "3600"]
func ParseRecordTag(tag []string) (*DNSRecord, error) {
    if len(tag) != 11 {
        return nil, errors.New("record tag must have exactly 11 elements")
    }
    if tag[0] != "record" {
        return nil, errors.New("first element must be 'record'")
    }
    
    ttl := uint32(3600) // default
    if tag[10] != "" {
        if parsed, err := strconv.ParseUint(tag[10], 10, 32); err == nil {
            ttl = uint32(parsed)
        }
    }
    
    return &DNSRecord{
        Type: tag[1],
        Name: tag[2],
        Data: tag[3:10],
        TTL:  ttl,
    }, nil
}
```

### 2. Certificate Integration

#### Certificate Event Structure (kind 30003)
```go
type CertificateEvent struct {
    TLD     string    // From "d" tag
    PEM     string    // Certificate content
    Expiry  int64     // From "expiry" tag (unix timestamp)
}

// Query certificate for TLD
func (c *NostrClient) FetchCertificate(pubkey, tld string) (*CertificateEvent, error) {
    filter := nostr.Filter{
        Kinds:   []int{30003},
        Authors: []string{pubkey},
        Tags: nostr.TagMap{
            "#d": []string{tld},
        },
        Limit: 1,
    }
    
    events := c.QuerySync([]nostr.Filter{filter})
    if len(events) == 0 {
        return nil, errors.New("no certificate found")
    }
    
    return parseCertificateEvent(events[0])
}
```

### 3. Cross-Platform Trust Store Integration

#### Trust Store Interface
```go
type TrustStore interface {
    AddCertificate(cert *x509.Certificate, domain string) error
    RemoveCertificate(domain string) error
    ListCertificates() ([]*x509.Certificate, error)
    ValidateCertificate(cert *x509.Certificate) error
}

type PlatformTrustStore struct {
    platform string
}

func NewTrustStore() TrustStore {
    switch runtime.GOOS {
    case "darwin":
        return &MacOSTrustStore{}
    case "linux":
        return &LinuxTrustStore{}
    case "windows":
        return &WindowsTrustStore{}
    default:
        return &GenericTrustStore{}
    }
}
```

#### Platform-Specific Implementations

##### macOS Trust Store
```go
type MacOSTrustStore struct{}

func (m *MacOSTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    // Write certificate to temp file
    tempFile, err := writeCertToTempFile(cert)
    if err != nil {
        return err
    }
    defer os.Remove(tempFile)
    
    // Use security command to add to System keychain
    cmd := exec.Command("security", 
        "add-trusted-cert", 
        "-d", 
        "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain",
        tempFile,
    )
    
    return cmd.Run()
}
```

##### Linux Trust Store
```go
type LinuxTrustStore struct{}

func (l *LinuxTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    certPath := fmt.Sprintf("/usr/local/share/ca-certificates/%s.crt", domain)
    
    // Write certificate file
    if err := writeCertToFile(cert, certPath); err != nil {
        return err
    }
    
    // Update CA certificates
    cmd := exec.Command("update-ca-certificates")
    return cmd.Run()
}
```

##### Windows Trust Store
```go
type WindowsTrustStore struct{}

func (w *WindowsTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    // Use PowerShell to import certificate
    tempFile, err := writeCertToTempFile(cert)
    if err != nil {
        return err
    }
    defer os.Remove(tempFile)
    
    psCmd := fmt.Sprintf(
        `Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root`,
        tempFile,
    )
    
    cmd := exec.Command("powershell", "-Command", psCmd)
    return cmd.Run()
}
```

### 4. DNS Server Implementation

#### Main Resolution Logic
```go
type DNSResolver struct {
    nostrClient *NostrClient
    trustStore  TrustStore
}

func (r *DNSResolver) ResolveNostrDomain(domain string, qtype uint16) (*dns.Msg, error) {
    // 1. Extract npub from domain
    npub, err := extractNpubFromDomain(domain)
    if err != nil {
        return nil, err
    }
    
    // 2. Convert npub to pubkey
    pubkey, err := convertNpubToPubkey(npub)
    if err != nil {
        return nil, err
    }
    
    // 3. Fetch DNS record event
    event, err := r.nostrClient.FetchDNSRecordEvent(pubkey)
    if err != nil {
        return nil, err
    }
    
    // 4. Parse DNS records from event
    records, err := parseDNSRecords(event)
    if err != nil {
        return nil, err
    }
    
    // 5. Check for certificate requirements
    if hasCertificateRecords(records) {
        tld := extractTLDFromDomain(domain)
        if cert, err := r.nostrClient.FetchCertificate(pubkey, tld); err == nil {
            if err := r.installCertificate(cert, domain); err != nil {
                log.Printf("Failed to install certificate for %s: %v", domain, err)
            }
        }
    }
    
    // 6. Generate DNS response
    return r.generateDNSResponse(domain, qtype, records)
}
```

#### Certificate Installation
```go
func (r *DNSResolver) installCertificate(certEvent *CertificateEvent, domain string) error {
    // Parse PEM certificate
    cert, err := parsePEMCertificate(certEvent.PEM)
    if err != nil {
        return fmt.Errorf("invalid PEM certificate: %w", err)
    }
    
    // Validate certificate
    if err := r.trustStore.ValidateCertificate(cert); err != nil {
        return fmt.Errorf("certificate validation failed: %w", err)
    }
    
    // Check expiration
    if cert.NotAfter.Before(time.Now()) {
        return errors.New("certificate has expired")
    }
    
    // Prompt user for consent (if interactive)
    if !r.getUserConsent(cert, domain) {
        return errors.New("user declined certificate installation")
    }
    
    // Add to trust store
    return r.trustStore.AddCertificate(cert, domain)
}
```

## Configuration

### Server Config
```go
type Config struct {
    Port         int      `yaml:"port"`
    Relays       []string `yaml:"relays"`
    ForwardDNS   []string `yaml:"forward_dns"`
    TTL          uint32   `yaml:"ttl"`
    CertPrompt   bool     `yaml:"cert_prompt"`
    CertAutoAdd  bool     `yaml:"cert_auto_add"`
}

var DefaultConfig = Config{
    Port: 5354,
    Relays: []string{
        "wss://relay.damus.io",
        "wss://nos.lol",
        "wss://relay.snort.social",
    },
    ForwardDNS: []string{"1.1.1.1", "1.0.0.1"},
    TTL:        3600,
    CertPrompt: true,
    CertAutoAdd: false,
}
```

## Usage Examples

### Running the Server
```bash
# Start DNS server on port 5354
./nodns-server -port 5354

# Start with custom config
./nodns-server -config /path/to/config.yaml

# Enable auto certificate installation (dangerous!)
./nodns-server -cert-auto-add
```

### Testing DNS Resolution
```bash
# Query A record
dig @localhost -p 5354 npub1abc.nostr A

# Query with certificate
dig @localhost -p 5354 npub1secure.nostr A
# (Certificate automatically fetched and installed)
```

## Security Considerations

### Certificate Installation
1. **User Consent**: Always prompt before modifying trust store
2. **Validation**: Verify certificate integrity and expiration
3. **Audit Logging**: Log all certificate installations
4. **Privilege Requirements**: Most platforms require admin/root access
5. **Cleanup**: Remove expired certificates automatically

### DNS Resolution
1. **Event Validation**: Verify Nostr event signatures
2. **Record Validation**: Validate DNS record formats
3. **Rate Limiting**: Prevent abuse of Nostr relays
4. **Caching**: Cache responses to reduce load

## Error Handling

### Common Errors
- Invalid npub format
- No DNS record event found
- Invalid record tag format
- Certificate validation failure
- Trust store access denied
- Network connectivity issues

### Graceful Degradation
- Fall back to NXDOMAIN if no records found
- Skip certificate installation if validation fails
- Forward non-nostr domains to upstream DNS
- Cache negative responses appropriately

## Testing Strategy

### Unit Tests
- Record tag parsing
- Certificate validation
- Trust store operations
- Domain extraction

### Integration Tests
- End-to-end DNS resolution
- Certificate fetching and installation
- Multi-platform trust store integration
- Relay connectivity and failover

### Manual Testing
- Test with real Nostr events
- Verify certificate installation on each platform
- Test with various DNS client tools (dig, nslookup)
- Performance testing with concurrent queries

## Next Steps

1. Implement core DNS resolution logic
2. Create Nostr client for record/certificate fetching
3. Build cross-platform trust store implementations
4. Add comprehensive error handling and logging
5. Create configuration management
6. Add metrics and monitoring
7. Package for multiple platforms