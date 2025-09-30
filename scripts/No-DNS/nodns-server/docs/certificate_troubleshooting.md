# Certificate Installation Troubleshooting Guide

## 🚨 macOS "Unknown format in import" Error - Complete Analysis

This document provides comprehensive analysis and solutions for the macOS certificate installation error: `SecCertificateCreateFromData: Unknown format in import`.

## 🔍 **Root Cause Analysis**

The error occurs when the macOS `security` command cannot parse the certificate file. Based on our implementation analysis, here are **ALL possible causes**:

### **1. PEM Format Issues (Most Common)**
- **Missing PEM headers**: Certificate lacks `-----BEGIN CERTIFICATE-----` / `-----END CERTIFICATE-----`
- **Incorrect PEM headers**: Wrong header type (e.g., `PRIVATE KEY` instead of `CERTIFICATE`)
- **Malformed PEM structure**: Headers/footers corrupted or incomplete
- **Extra whitespace**: Leading/trailing spaces or tabs around headers
- **Wrong line endings**: Windows `\r\n` vs Unix `\n` line endings
- **Missing trailing newline**: Some parsers require PEM to end with `\n`

### **2. Certificate Content Issues**
- **Invalid Base64 encoding**: Certificate data between headers is corrupted
- **Truncated certificate**: Incomplete certificate data from network issues
- **Double encoding**: Certificate data encoded twice (base64 of base64)
- **Binary data**: Raw DER format instead of PEM format
- **Empty certificate**: Zero-length or whitespace-only content

### **3. Character Encoding Problems**
- **UTF-8 encoding issues**: Non-ASCII characters in certificate data
- **BOM (Byte Order Mark)**: UTF-8 BOM at start of file confusing parser
- **Character set corruption**: Data corruption during string handling
- **Unicode normalization**: Different Unicode forms causing issues

### **4. File System Issues**
- **File permissions**: Temp file not readable by `security` command
- **File size**: Zero-byte file or extremely large file
- **File corruption**: Disk errors or incomplete writes
- **Path issues**: Special characters in temp file path
- **Concurrent access**: File being modified while `security` reads it

### **5. macOS Security Command Issues**
- **Command syntax**: Wrong arguments to `security add-trusted-cert`
- **Keychain permissions**: Cannot write to System keychain
- **Security policies**: System policy blocking certificate installation
- **SIP (System Integrity Protection)**: Preventing keychain modification
- **Gatekeeper interference**: Security restrictions blocking operation

## 🛠️ **Implemented Solutions**

### **1. Enhanced PEM Validation & Cleaning**

**Location**: [`nodns-server/internal/nostr/client.go:validateAndCleanPEM()`](nodns-server/internal/nostr/client.go)

```go
// Comprehensive PEM validation and cleaning
func validateAndCleanPEM(pemData, tld string) (string, error) {
    // 1. Remove UTF-8 BOM
    // 2. Normalize line endings
    // 3. Trim whitespace
    // 4. Validate PEM structure
    // 5. Check certificate headers
    // 6. Detect binary data
    // 7. Ensure trailing newline
    // 8. Validate PEM decoding
    // 9. Validate X.509 parsing
}
```

### **2. Comprehensive File Writing Diagnostics**

**Location**: [`nodns-server/internal/certs/truststore.go:writePEMToTempFile()`](nodns-server/internal/certs/truststore.go)

```go
func writePEMToTempFile(pemData, domain string) (string, error) {
    // 1. PEM format diagnosis
    // 2. Data cleaning and normalization
    // 3. File write validation
    // 4. Post-write verification
}
```

### **3. Multiple Security Command Attempts**

**Location**: [`nodns-server/internal/certs/truststore.go:AddCertificatePEM()`](nodns-server/internal/certs/truststore.go)

The system now tries multiple approaches in order:
1. `security add-trusted-cert` (system keychain)
2. `security add-certificates` (system keychain)
3. `security import` (system keychain)
4. `security add-trusted-cert` (user keychain) **← SAFER FALLBACK**
5. `security add-certificates` (user keychain)
6. `security import` (user keychain)

### **4. Comprehensive Diagnostic Logging**

All certificate operations now include detailed logging with `CERT_DIAG:` prefix:
- PEM data validation results
- File writing diagnostics
- Security command attempts
- Error analysis

## 🧪 **Testing & Diagnostics**

### **Certificate Format Test Script**

Run the comprehensive diagnostic script:

```bash
cd nodns-server
./scripts/test-cert-format.sh
```

This script tests:
- Various PEM formats (with/without trailing newlines, different line endings)
- Multiple security commands
- File validation
- System compatibility

### **Enhanced Server Logging**

When running with certificate functionality enabled:

```bash
# Build server
make build

# Run with detailed logging
./nodns-server -cert-auto-install=true -log-level=debug
```

Look for log entries with these prefixes:
- `CERT_VALIDATION:` - PEM validation results
- `CERT_DIAG:` - Diagnostic information
- `SECURITY ERROR:` - Installation failures
- `SECURITY AUDIT:` - Installation attempts

## 🔧 **Troubleshooting Steps**

### **Step 1: Verify Certificate Source**
```bash
# Check the Nostr event content directly
# Look for proper PEM structure in the kind 30003 event
```

### **Step 2: Test Certificate Format**
```bash
# Use OpenSSL to validate
echo "$CERT_DATA" | openssl x509 -text -noout

# Check for common issues
hexdump -C cert.pem | head  # Look for BOM or binary data
```

### **Step 3: Test Security Commands Manually**
```bash
# Try user keychain first (safer)
security add-trusted-cert -d cert.pem

# Check if it worked
security find-certificate -c "your-domain"
```

### **Step 4: Check System Restrictions**
```bash
# Check SIP status
csrutil status

# Check keychain access
security list-keychains

# Test with a known good certificate
```

## 🚦 **Error Resolution Priority**

1. **Most Likely**: PEM format issues (trailing newlines, line endings)
2. **Common**: File permissions or keychain access issues
3. **Possible**: Character encoding problems (UTF-8 BOM)
4. **Rare**: System security restrictions or SIP interference
5. **Very Rare**: Binary data or double-encoding issues

## 📊 **Success Indicators**

When the fixes work, you should see:
```
CERT_VALIDATION: Successfully validated PEM certificate for TLD nostr (1234 chars)
CERT_DIAG: File validation successful
CERT_DIAG: Trying add-trusted-cert (user keychain) for domain.nostr
SECURITY CRITICAL: Successfully added certificate for domain.nostr using add-trusted-cert (user keychain)
```

## 🔒 **Security Notes**

- **User keychain fallback** is safer than system keychain
- All certificate operations are extensively logged
- Operations require explicit user consent via config flags
- Comprehensive audit trail for security compliance

## 🆘 **If Issues Persist**

1. Run the diagnostic script: `./scripts/test-cert-format.sh`
2. Check system logs: `log show --predicate 'process == "security"'`
3. Test with a known-good certificate file
4. Verify macOS version compatibility
5. Check for system security restrictions

The enhanced implementation should resolve the majority of "Unknown format in import" errors through comprehensive PEM validation, multiple installation attempts, and safe fallback options.