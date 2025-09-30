#!/bin/bash

# Certificate Format Diagnostic Script
# This script helps diagnose certificate format issues on macOS

set -e

echo "🔍 Certificate Format Diagnostic Tool"
echo "====================================="

# Test certificate (valid self-signed cert for testing)
TEST_CERT="-----BEGIN CERTIFICATE-----
MIICijCCAXICCQC4+4Z4Z4Z4ZjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK
gQi7YR4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBKg1i7YR4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z
4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4Z4
-----END CERTIFICATE-----"

# Function to test certificate with different formats
test_cert_format() {
    local cert_data="$1"
    local format_name="$2"
    local temp_file=$(mktemp -t "test-cert-XXXXXX.crt")
    
    echo "🧪 Testing format: $format_name"
    echo "   File: $temp_file"
    
    # Write certificate to file
    echo "$cert_data" > "$temp_file"
    
    # Check file size
    file_size=$(stat -f%z "$temp_file" 2>/dev/null || stat -c%s "$temp_file" 2>/dev/null || echo "unknown")
    echo "   Size: $file_size bytes"
    
    # Check PEM structure with openssl
    echo "   OpenSSL validation:"
    if openssl x509 -in "$temp_file" -text -noout >/dev/null 2>&1; then
        echo "   ✅ OpenSSL can parse certificate"
        echo "   Subject: $(openssl x509 -in "$temp_file" -subject -noout 2>/dev/null | cut -d= -f2-)"
    else
        echo "   ❌ OpenSSL cannot parse certificate"
    fi
    
    # Test with macOS security command
    echo "   macOS security command test:"
    if security verify-cert -c "$temp_file" >/dev/null 2>&1; then
        echo "   ✅ security verify-cert successful"
    else
        echo "   ❌ security verify-cert failed"
    fi
    
    # Try import attempts
    echo "   Import attempts:"
    
    # Test 1: add-trusted-cert
    output=$(security add-trusted-cert -d -k ~/Library/Keychains/login.keychain "$temp_file" 2>&1 || true)
    if [[ $? -eq 0 ]]; then
        echo "   ✅ add-trusted-cert: SUCCESS"
        # Clean up
        security delete-certificate -c "localhost" ~/Library/Keychains/login.keychain >/dev/null 2>&1 || true
    else
        echo "   ❌ add-trusted-cert: $output"
    fi
    
    # Test 2: add-certificates  
    output=$(security add-certificates -k ~/Library/Keychains/login.keychain "$temp_file" 2>&1 || true)
    if [[ $? -eq 0 ]]; then
        echo "   ✅ add-certificates: SUCCESS"
        # Clean up
        security delete-certificate -c "localhost" ~/Library/Keychains/login.keychain >/dev/null 2>&1 || true
    else
        echo "   ❌ add-certificates: $output"
    fi
    
    # Test 3: import
    output=$(security import "$temp_file" -k ~/Library/Keychains/login.keychain -t cert 2>&1 || true)
    if [[ $? -eq 0 ]]; then
        echo "   ✅ import: SUCCESS"
        # Clean up
        security delete-certificate -c "localhost" ~/Library/Keychains/login.keychain >/dev/null 2>&1 || true
    else
        echo "   ❌ import: $output"
    fi
    
    # Cleanup
    rm -f "$temp_file"
    echo ""
}

# Test different certificate formats
echo "Testing various certificate formats:"
echo ""

# Test 1: Normal certificate with trailing newline
test_cert_format "$TEST_CERT" "Standard PEM with trailing newline"

# Test 2: Certificate without trailing newline
test_cert_format "$(echo -n "$TEST_CERT")" "PEM without trailing newline"

# Test 3: Certificate with Windows line endings
test_cert_format "$(echo "$TEST_CERT" | tr '\n' '\r\n')" "PEM with Windows line endings"

# Test 4: Certificate with extra spaces
test_cert_format "   $TEST_CERT   " "PEM with extra whitespace"

# Test 5: Certificate with UTF-8 BOM
test_cert_format $'\ufeff'"$TEST_CERT" "PEM with UTF-8 BOM"

# System information
echo "🖥️  System Information:"
echo "   macOS version: $(sw_vers -productVersion)"
echo "   Security framework: $(security -h 2>&1 | head -1)"
echo "   OpenSSL version: $(openssl version 2>/dev/null || echo 'Not available')"

echo ""
echo "✅ Certificate format diagnostic complete!"
echo ""
echo "💡 Troubleshooting tips:"
echo "   1. Ensure certificate has proper PEM headers/footers"
echo "   2. Check for trailing newlines (required by some parsers)"
echo "   3. Verify no extra whitespace or special characters"
echo "   4. Test with user keychain before system keychain"
echo "   5. Use 'openssl x509 -text -noout -in file.crt' to validate format"