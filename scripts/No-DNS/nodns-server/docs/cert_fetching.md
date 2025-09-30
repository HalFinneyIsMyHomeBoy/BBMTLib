# Certificate Fetching and Trust Store Integration

## ⚠️ SECURITY WARNING ⚠️

**This document describes DANGEROUS functionality that can compromise system security. The automatic installation of certificates from Nostr events can allow malicious actors to intercept encrypted traffic and perform man-in-the-middle attacks. Use only in isolated testing environments.**

## Overview

This document details the certificate fetching process for the `nodns-server`, including how certificates are retrieved from Nostr events and integrated with system trust stores across different platforms.

## Unified Event Fetching Strategy

Instead of making separate queries for DNS records (kind 11111) and certificates (kind 30003), we use a single subscription to fetch both event types for a given pubkey:

```go
// Single subscription for both DNS records and certificates
filter := nostr.Filter{
    Kinds:   []int{11111, 30003}, // Both DNS records and certificates
    Authors: []string{pubkey},
    Limit:   50, // Allow multiple certificate events (different TLDs)
}
```

## Event Processing Workflow

```
DNS Query: npub1abc.nostr
    ↓
1. Extract pubkey from domain
    ↓
2. Subscribe to relays with unified filter (kinds 11111, 30003)
    ↓
3. Process events as they arrive:
   - kind 11111: Parse DNS records
   - kind 30003: Parse certificates by TLD
    ↓
4. Generate DNS response from records
    ↓
5. [DANGEROUS] Install certificates if found and valid
    ↓
6. Return DNS response
```

## Implementation

### 1. Unified Event Fetcher

```go
type EventBundle struct {
    DNSRecords   *nostr.Event              // kind 11111 event
    Certificates map[string]*nostr.Event   // TLD -> kind 30003 event
}

func (c *NostrClient) FetchEventsForPubkey(pubkey string) (*EventBundle, error) {
    filter := nostr.Filter{
        Kinds:   []int{11111, 30003},
        Authors: []string{pubkey},
        Limit:   50, // Allow multiple certificates
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    bundle := &EventBundle{
        Certificates: make(map[string]*nostr.Event),
    }
    
    for _, relayURL := range c.relays {
        relay, err := nostr.RelayConnect(ctx, relayURL)
        if err != nil {
            continue
        }
        
        sub, err := relay.Subscribe(ctx, []nostr.Filter{filter})
        if err != nil {
            relay.Close()
            continue
        }
        
        // Collect events
        eventTimeout := time.After(5 * time.Second)
        
    eventLoop:
        for {
            select {
            case event := <-sub.Events:
                switch event.Kind {
                case 11111:
                    // Keep latest DNS record event
                    if bundle.DNSRecords == nil || event.CreatedAt > bundle.DNSRecords.CreatedAt {
                        bundle.DNSRecords = event
                    }
                case 30003:
                    // Extract TLD from 'd' tag
                    tld := extractTLDFromEvent(event)
                    if tld != "" {
                        // Keep latest certificate per TLD
                        if existing, exists := bundle.Certificates[tld]; !exists || event.CreatedAt > existing.CreatedAt {
                            bundle.Certificates[tld] = event
                        }
                    }
                }
            case <-sub.EndOfStoredEvents:
                break eventLoop
            case <-eventTimeout:
                break eventLoop
            }
        }
        
        sub.Unsub()
        relay.Close()
        
        // Stop if we have DNS records (certificates are optional)
        if bundle.DNSRecords != nil {
            break
        }
    }
    
    return bundle, nil
}

func extractTLDFromEvent(event *nostr.Event) string {
    for _, tag := range event.Tags {
        if len(tag) >= 2 && tag[0] == "d" {
            return tag[1]
        }
    }
    return ""
}
```

### 2. Certificate Processing

```go
type Certificate struct {
    TLD         string
    PEM         string
    X509Cert    *x509.Certificate
    Expiry      time.Time
    Valid       bool
    Domain      string // The full domain this cert is for
    Fingerprint string // SHA-256 fingerprint for logging
}

func (r *DNSResolver) processCertificates(bundle *EventBundle, domain string) []*Certificate {
    var certificates []*Certificate
    
    domainTLD := extractTLDFromDomain(domain)
    
    for tld, certEvent := range bundle.Certificates {
        cert := &Certificate{
            TLD:    tld,
            PEM:    certEvent.Content,
            Domain: fmt.Sprintf("%s.%s", extractNpubFromDomain(domain), tld),
        }
        
        // Parse PEM certificate
        if x509Cert, err := parsePEMCertificate(cert.PEM); err == nil {
            cert.X509Cert = x509Cert
            cert.Expiry = x509Cert.NotAfter
            cert.Valid = x509Cert.NotAfter.After(time.Now())
            cert.Fingerprint = calculateFingerprint(x509Cert)
            
            // SECURITY LOG: Always log certificate processing
            log.Printf("SECURITY: Processing certificate for %s (fingerprint: %s, expires: %s)", 
                cert.Domain, cert.Fingerprint, cert.Expiry.Format("2006-01-02"))
        } else {
            log.Printf("SECURITY: Invalid certificate for %s: %v", cert.Domain, err)
        }
        
        certificates = append(certificates, cert)
        
        // DANGEROUS: Install certificate if it matches the queried domain TLD
        if tld == domainTLD && cert.Valid && r.config.CertAutoInstall {
            log.Printf("SECURITY WARNING: Auto-installing certificate for %s", cert.Domain)
            go r.installCertificateAsync(cert)
        }
    }
    
    return certificates
}

func calculateFingerprint(cert *x509.Certificate) string {
    hash := sha256.Sum256(cert.Raw)
    return fmt.Sprintf("%x", hash)
}
```

### 3. Cross-Platform Trust Store Integration

#### Trust Store Interface
```go
type TrustStore interface {
    AddCertificate(cert *x509.Certificate, domain string) error
    RemoveCertificate(domain string) error
    HasCertificate(domain string) (bool, error)
    ValidateCertificate(cert *x509.Certificate) error
    RequiresElevation() bool
}
```

#### macOS Implementation (DANGEROUS)
```go
type MacOSTrustStore struct {
    keychain string
}

func NewMacOSTrustStore() *MacOSTrustStore {
    return &MacOSTrustStore{
        keychain: "/Library/Keychains/System.keychain",
    }
}

func (m *MacOSTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    // SECURITY LOG: Critical security operation
    log.Printf("SECURITY CRITICAL: Adding certificate to macOS keychain for %s", domain)
    
    // Create temporary certificate file
    tempFile, err := m.writeCertToTempFile(cert, domain)
    if err != nil {
        return fmt.Errorf("failed to write cert to temp file: %w", err)
    }
    defer os.Remove(tempFile)
    
    // Check if certificate already exists
    if exists, _ := m.HasCertificate(domain); exists {
        log.Printf("Certificate for %s already exists, skipping", domain)
        return nil
    }
    
    // DANGEROUS: Add to System keychain without user consent
    cmd := exec.Command("security", 
        "add-trusted-cert", 
        "-d",                    // Add to admin cert store
        "-r", "trustRoot",       // Set trust settings  
        "-p", "ssl",            // Policy (SSL)
        "-k", m.keychain,       // Target keychain
        tempFile,
    )
    
    if output, err := cmd.CombinedOutput(); err != nil {
        log.Printf("SECURITY ERROR: Failed to add certificate: %v (output: %s)", err, output)
        return fmt.Errorf("security command failed: %w (output: %s)", err, output)
    }
    
    log.Printf("SECURITY CRITICAL: Successfully added certificate for %s to macOS keychain", domain)
    return nil
}

func (m *MacOSTrustStore) HasCertificate(domain string) (bool, error) {
    cmd := exec.Command("security", "find-certificate", "-c", domain, m.keychain)
    err := cmd.Run()
    return err == nil, nil
}

func (m *MacOSTrustStore) RequiresElevation() bool {
    return true // Requires admin privileges
}
```

#### Linux Implementation (DANGEROUS)
```go
type LinuxTrustStore struct {
    certDir string
}

func NewLinuxTrustStore() *LinuxTrustStore {
    return &LinuxTrustStore{
        certDir: "/usr/local/share/ca-certificates",
    }
}

func (l *LinuxTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    // SECURITY LOG: Critical security operation
    log.Printf("SECURITY CRITICAL: Adding certificate to Linux CA store for %s", domain)
    
    certPath := filepath.Join(l.certDir, fmt.Sprintf("nostr-%s.crt", domain))
    
    // Check if certificate already exists
    if exists, _ := l.HasCertificate(domain); exists {
        log.Printf("Certificate for %s already exists, skipping", domain)
        return nil
    }
    
    // Write certificate file
    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: cert.Raw,
    })
    
    if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
        return fmt.Errorf("failed to write certificate: %w", err)
    }
    
    // DANGEROUS: Update CA certificates system-wide
    cmd := exec.Command("update-ca-certificates")
    if output, err := cmd.CombinedOutput(); err != nil {
        os.Remove(certPath) // Cleanup on failure
        log.Printf("SECURITY ERROR: Failed to update CA certificates: %v (output: %s)", err, output)
        return fmt.Errorf("update-ca-certificates failed: %w (output: %s)", err, output)
    }
    
    log.Printf("SECURITY CRITICAL: Successfully added certificate for %s to Linux CA store", domain)
    return nil
}

func (l *LinuxTrustStore) HasCertificate(domain string) (bool, error) {
    certPath := filepath.Join(l.certDir, fmt.Sprintf("nostr-%s.crt", domain))
    _, err := os.Stat(certPath)
    return err == nil, nil
}

func (l *LinuxTrustStore) RequiresElevation() bool {
    return true // Requires sudo
}
```

#### Windows Implementation (DANGEROUS)
```go
type WindowsTrustStore struct{}

func NewWindowsTrustStore() *WindowsTrustStore {
    return &WindowsTrustStore{}
}

func (w *WindowsTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
    // SECURITY LOG: Critical security operation
    log.Printf("SECURITY CRITICAL: Adding certificate to Windows certificate store for %s", domain)
    
    // Check if certificate already exists
    if exists, _ := w.HasCertificate(domain); exists {
        log.Printf("Certificate for %s already exists, skipping", domain)
        return nil
    }
    
    // Write certificate to temp file
    tempFile, err := w.writeCertToTempFile(cert, domain)
    if err != nil {
        return fmt.Errorf("failed to write cert to temp file: %w", err)
    }
    defer os.Remove(tempFile)
    
    // DANGEROUS: Import using PowerShell without user consent
    psCmd := fmt.Sprintf(
        `Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root`,
        tempFile,
    )
    
    cmd := exec.Command("powershell", "-Command", psCmd)
    if output, err := cmd.CombinedOutput(); err != nil {
        log.Printf("SECURITY ERROR: Failed to import certificate: %v (output: %s)", err, output)
        return fmt.Errorf("powershell import failed: %w (output: %s)", err, output)
    }
    
    log.Printf("SECURITY CRITICAL: Successfully added certificate for %s to Windows certificate store", domain)
    return nil
}

func (w *WindowsTrustStore) HasCertificate(domain string) (bool, error) {
    // Query certificate store
    psCmd := fmt.Sprintf(
        `Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*%s*"}`,
        domain,
    )
    
    cmd := exec.Command("powershell", "-Command", psCmd)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return false, err
    }
    
    return len(strings.TrimSpace(string(output))) > 0, nil
}

func (w *WindowsTrustStore) RequiresElevation() bool {
    return true // Requires administrator privileges
}
```

### 4. Certificate Installation with Safety Checks

```go
func (r *DNSResolver) installCertificateAsync(cert *Certificate) {
    // Don't block DNS response on certificate installation
    go func() {
        if err := r.installCertificate(cert); err != nil {
            log.Printf("SECURITY ERROR: Failed to install certificate for %s: %v", cert.Domain, err)
        }
    }()
}

func (r *DNSResolver) installCertificate(cert *Certificate) error {
    // SECURITY AUDIT LOG
    log.Printf("SECURITY AUDIT: Attempting to install certificate for %s (fingerprint: %s)", 
        cert.Domain, cert.Fingerprint)
    
    // Validate certificate first
    if err := r.trustStore.ValidateCertificate(cert.X509Cert); err != nil {
        log.Printf("SECURITY ERROR: Certificate validation failed for %s: %v", cert.Domain, err)
        return fmt.Errorf("certificate validation failed: %w", err)
    }
    
    // Check expiration
    if cert.X509Cert.NotAfter.Before(time.Now()) {
        log.Printf("SECURITY WARNING: Rejecting expired certificate for %s", cert.Domain)
        return errors.New("certificate has expired")
    }
    
    // Check if certificate is self-signed (potential security risk)
    if cert.X509Cert.Issuer.String() == cert.X509Cert.Subject.String() {
        log.Printf("SECURITY WARNING: Self-signed certificate detected for %s", cert.Domain)
        if r.config.CertSkipSelfSigned {
            return errors.New("self-signed certificates are disabled")
        }
    }
    
    // Check if we need elevation and handle accordingly
    if r.trustStore.RequiresElevation() && !r.hasElevatedPrivileges() {
        log.Printf("SECURITY ERROR: Certificate installation requires elevation for %s", cert.Domain)
        return errors.New("insufficient privileges for certificate installation")
    }
    
    // DANGEROUS: Install certificate
    if err := r.trustStore.AddCertificate(cert.X509Cert, cert.Domain); err != nil {
        log.Printf("SECURITY ERROR: Failed to add certificate to trust store for %s: %v", cert.Domain, err)
        return fmt.Errorf("failed to add certificate to trust store: %w", err)
    }
    
    // SECURITY AUDIT LOG: Successful installation
    log.Printf("SECURITY AUDIT: Successfully installed certificate for %s (expires: %s)", 
        cert.Domain, cert.Expiry.Format("2006-01-02"))
    
    // Optionally notify monitoring systems
    r.auditCertificateInstallation(cert, true, "")
    
    return nil
}

func (r *DNSResolver) auditCertificateInstallation(cert *Certificate, success bool, errorMsg string) {
    event := CertInstallEvent{
        Domain:      cert.Domain,
        TLD:         cert.TLD,
        Timestamp:   time.Now(),
        Success:     success,
        Error:       errorMsg,
        Fingerprint: cert.Fingerprint,
        Expiry:      cert.Expiry,
    }
    
    // Log to audit system
    auditJSON, _ := json.Marshal(event)
    log.Printf("CERT_INSTALL_AUDIT: %s", auditJSON)
}
```

## Configuration Options

```go
type CertConfig struct {
    AutoInstall      bool     `yaml:"auto_install"`      // DANGEROUS: Auto-install without prompting
    PromptUser       bool     `yaml:"prompt_user"`       // Prompt before each installation
    RequiredTLDs     []string `yaml:"required_tlds"`     // Only install certs for these TLDs
    SkipExpired      bool     `yaml:"skip_expired"`      // Skip expired certificates
    SkipSelfSigned   bool     `yaml:"skip_self_signed"`  // Skip self-signed certificates
    MaxAge           int      `yaml:"max_age_days"`      // Skip certs older than X days
    AuditLog         string   `yaml:"audit_log"`         // Path to audit log file
    DisableDangerous bool     `yaml:"disable_dangerous"` // Completely disable cert installation
}

var SafeDefaults = CertConfig{
    AutoInstall:      false, // NEVER enable by default
    PromptUser:       true,  // Always prompt
    SkipExpired:      true,
    SkipSelfSigned:   true,  // Skip self-signed for safety
    MaxAge:           365,   // Only install recent certificates
    DisableDangerous: true,  // Disable by default
}
```

## Security Considerations

### 1. Certificate Validation (Insufficient Protection)
- Basic PEM format validation
- Expiration date checking
- Self-signed certificate detection
- **WARNING: These checks are insufficient to prevent malicious certificates**

### 2. Trust Store Modifications (EXTREMELY DANGEROUS)
- Requires administrative privileges on all platforms
- Modifies system-wide trust settings
- Can enable man-in-the-middle attacks
- **No reliable way to verify certificate legitimacy from Nostr events alone**

### 3. Attack Scenarios
- **Malicious Relay**: Attacker controls relay and serves malicious certificates
- **Key Compromise**: Attacker compromises Nostr private key and publishes malicious certs
- **BGP Hijacking**: Attacker intercepts traffic using installed certificates
- **Social Engineering**: Attacker tricks users into trusting malicious domains

### 4. Insufficient Mitigations
- Event signature validation only proves the key holder published the cert
- Certificate expiration doesn't prevent malicious short-lived certificates
- Self-signed detection doesn't prevent malicious CA-signed certificates
- User prompts can be bypassed or ignored

## Monitoring and Logging

### Critical Security Events
```go
type CertInstallEvent struct {
    Domain      string    `json:"domain"`
    TLD         string    `json:"tld"`
    Timestamp   time.Time `json:"timestamp"`
    Success     bool      `json:"success"`
    Error       string    `json:"error,omitempty"`
    Fingerprint string    `json:"fingerprint"`
    Expiry      time.Time `json:"expiry"`
    Source      string    `json:"source"` // "nostr"
    Risk        string    `json:"risk"`   // "HIGH", "CRITICAL"
}
```

### Essential Logging
- Every certificate installation attempt (success/failure)
- Certificate fingerprints and expiration dates
- Source of certificate (Nostr event ID)
- User consent (if prompted)
- System privilege escalation events
- Trust store modification attempts

## Testing (In Isolated Environments Only)

### Unit Tests
- Certificate parsing and validation
- Trust store operations (mocked)
- Event filtering and processing
- Security validation logic

### Integration Tests (DANGEROUS)
- **Only run in completely isolated VMs**
- End-to-end certificate fetching and installation
- Multi-platform trust store integration
- Malicious certificate handling
- Permission handling

### Security Testing
- Test with malicious/crafted certificates
- Test privilege escalation scenarios
- Test certificate chain validation bypass
- Test with expired/revoked certificates

## Recommendations for Safe Usage

### 1. Default Configuration
- **NEVER** enable auto-installation by default
- Always prompt users before certificate installation
- Disable certificate functionality entirely by default
- Require explicit opt-in with clear warnings

### 2. Runtime Safety
- Run in isolated environments only
- Monitor all certificate installations
- Implement certificate allowlists where possible
- Provide easy rollback/removal mechanisms

### 3. User Education
- Clear documentation about security risks
- Prominent warnings in all interfaces
- Require users to acknowledge risks
- Provide safe alternatives where possible

## Conclusion

**This certificate fetching functionality is inherently dangerous and should not be used in production environments.** While it demonstrates the technical feasibility of distributed certificate management via Nostr, it introduces significant security risks that outweigh any potential benefits in most scenarios.

Consider this functionality as a proof-of-concept only, suitable for research and isolated testing environments where the security implications are fully understood and accepted.