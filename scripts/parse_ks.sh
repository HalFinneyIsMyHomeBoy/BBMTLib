#!/bin/bash

# Script to parse .ks files and print their contents
# Usage: ./parse_ks.sh <filename.ks>

set -e  # Exit on error

if [ $# -ne 1 ]; then
    echo "Usage: $0 <filename.ks>"
    echo "Example: $0 peer1.ks"
    exit 1
fi

filename="$1"

# Check if file exists
if [ ! -f "$filename" ]; then
    echo "Error: File '$filename' not found"
    exit 1
fi

# Check if file has .ks extension
if [[ ! "$filename" == *.ks ]]; then
    echo "Warning: File doesn't have .ks extension"
fi

echo "=== Parsing Keyshare File: $filename ==="
echo

# Check for required commands
if ! command -v base64 >/dev/null 2>&1; then
    echo "✗ Error: base64 command not found"
    echo "=== Raw File Content ==="
    cat "$filename"
    exit 1
fi

# Read the file and decode base64
echo "=== Base64 Decoded Content ==="
decoded_content=$(cat "$filename" | base64 -d 2>/dev/null)

if [ $? -eq 0 ]; then
    # Check if the decoded content is valid JSON
    if command -v jq >/dev/null 2>&1; then
        # Use jq for JSON validation and formatting
        if echo "$decoded_content" | jq . >/dev/null 2>&1; then
            echo "✓ Valid JSON detected (using jq)"
            echo
            echo "=== Formatted JSON Content ==="
            echo "$decoded_content" | jq .
        else
            echo "⚠ Warning: Decoded content is not valid JSON"
            echo
            echo "=== Raw Decoded Content ==="
            echo "$decoded_content"
        fi
    else
        # Fallback: basic JSON validation using bash
        if [[ "$decoded_content" =~ ^[[:space:]]*\{.*\}[[:space:]]*$ ]]; then
            echo "✓ Valid JSON detected (basic validation)"
            echo
            echo "=== Raw Decoded Content ==="
            echo "$decoded_content"
        else
            echo "⚠ Warning: Decoded content is not valid JSON"
            echo
            echo "=== Raw Decoded Content ==="
            echo "$decoded_content"
        fi
    fi
else
    echo "✗ Error: Failed to decode base64 content"
    echo
    echo "=== Raw File Content ==="
    cat "$filename"
    exit 1
fi

echo
echo "=== File Information ==="
echo "File size: $(wc -c < "$filename") bytes"
echo "File permissions: $(ls -l "$filename" | awk '{print $1}')"

# macOS compatible stat command
if stat -c %y "$filename" >/dev/null 2>&1; then
    echo "Last modified: $(stat -c %y "$filename")"
elif stat -f %Sm "$filename" >/dev/null 2>&1; then
    echo "Last modified: $(stat -f %Sm "$filename")"
else
    echo "Last modified: Unknown"
fi

# Try to extract key information if it's valid JSON
if [ ! -z "$decoded_content" ]; then
    echo
    echo "=== Key Information ==="
    
    if command -v jq >/dev/null 2>&1; then
        # Use jq for efficient JSON parsing
        echo "$decoded_content" | jq -r '
            # Extract public key
            if has("pub_key") then "Public Key: " + .pub_key else empty end,
            
            # Extract chain code
            if has("chain_code_hex") then "Chain Code (Hex): " + .chain_code_hex else empty end,
            
            # Extract local party key
            if has("local_party_key") then "Local Party Key: " + .local_party_key else empty end,
            
            # Extract keygen committee keys count
            if has("keygen_committee_keys") and (.keygen_committee_keys | length > 0) then
                "Keygen Committee Keys: " + (.keygen_committee_keys | length | tostring) + " keys",
                (.keygen_committee_keys[0:5] | to_entries | map("  [" + (.key + 1 | tostring) + "] " + .value) | .[]),
                if (.keygen_committee_keys | length > 5) then
                    "  ... and " + ((.keygen_committee_keys | length) - 5 | tostring) + " more keys"
                else empty end
            else empty end,
            
            # Check for ECDSA local data
            if has("ecdsa_local_data") and (.ecdsa_local_data | type == "object") then
                "",
                "ECDSA Local Data: Present",
                if (.ecdsa_local_data.ECDSAPub) then "  ECDSA Public Key: " + .ecdsa_local_data.ECDSAPub else empty end,
                if (.ecdsa_local_data.BigXj) then "  BigXj: " + .ecdsa_local_data.BigXj else empty end
            else empty end
        '
    else
        # Fallback: pure bash JSON parsing (basic but functional)
        echo "Using basic bash parsing (install jq for better performance)"
        
        # Extract public key using grep/sed
        pub_key=$(echo "$decoded_content" | grep -o '"pub_key"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"pub_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$pub_key" ]; then
            echo "Public Key: $pub_key"
        fi
        
        # Extract chain code
        chain_code=$(echo "$decoded_content" | grep -o '"chain_code_hex"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"chain_code_hex"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$chain_code" ]; then
            echo "Chain Code (Hex): $chain_code"
        fi
        
        # Extract local party key
        local_party_key=$(echo "$decoded_content" | grep -o '"local_party_key"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"local_party_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [ -n "$local_party_key" ]; then
            echo "Local Party Key: $local_party_key"
        fi
        
        # Extract keygen committee keys count (simplified)
        committee_keys_section=$(echo "$decoded_content" | grep -A 10 '"keygen_committee_keys"')
        if [ -n "$committee_keys_section" ]; then
            # Count keys by counting lines with quotes (basic approach)
            key_count=$(echo "$committee_keys_section" | grep -c '"[^"]*"' || echo "0")
            echo "Keygen Committee Keys: $key_count keys (estimated)"
        fi
        
        # Check for ECDSA data
        if echo "$decoded_content" | grep -q '"ecdsa_local_data"'; then
            echo
            echo "ECDSA Local Data: Present"
            
            # Extract ECDSA public key
            ecdsa_pub=$(echo "$decoded_content" | grep -o '"ECDSAPub"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"ECDSAPub"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
            if [ -n "$ecdsa_pub" ]; then
                echo "  ECDSA Public Key: $ecdsa_pub"
            fi
            
            # Extract BigXj
            big_xj=$(echo "$decoded_content" | grep -o '"BigXj"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"BigXj"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
            if [ -n "$big_xj" ]; then
                echo "  BigXj: $big_xj"
            fi
        fi
    fi
fi

echo
echo "=== Parsing Complete ===" 