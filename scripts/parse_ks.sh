#!/bin/bash

# Script to parse .ks files and print their contents
# Usage: ./parse_ks.sh <filename.ks>

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

# Read the file and decode base64
echo "=== Base64 Decoded Content ==="
if command -v base64 >/dev/null 2>&1; then
    # Decode base64 and format JSON
    decoded_content=$(cat "$filename" | base64 -d 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        # Check if the decoded content is valid JSON
        if echo "$decoded_content" | python3 -m json.tool >/dev/null 2>&1; then
            echo "✓ Valid JSON detected"
            echo
            echo "=== Formatted JSON Content ==="
            echo "$decoded_content" | python3 -m json.tool
        else
            echo "⚠ Warning: Decoded content is not valid JSON"
            echo
            echo "=== Raw Decoded Content ==="
            echo "$decoded_content"
        fi
    else
        echo "✗ Error: Failed to decode base64 content"
        echo
        echo "=== Raw File Content ==="
        cat "$filename"
    fi
else
    echo "✗ Error: base64 command not found"
    echo
    echo "=== Raw File Content ==="
    cat "$filename"
fi

echo
echo "=== File Information ==="
echo "File size: $(wc -c < "$filename") bytes"
echo "File permissions: $(ls -l "$filename" | awk '{print $1}')"
echo "Last modified: $(stat -c %y "$filename" 2>/dev/null || stat -f %Sm "$filename" 2>/dev/null || echo "Unknown")"

# Try to extract key information if it's valid JSON
if [ ! -z "$decoded_content" ] && echo "$decoded_content" | python3 -m json.tool >/dev/null 2>&1; then
    echo
    echo "=== Key Information ==="
    
    # Extract public key
    pub_key=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('pub_key', 'Not found'))" 2>/dev/null)
    if [ "$pub_key" != "Not found" ]; then
        echo "Public Key: $pub_key"
    fi
    
    # Extract chain code
    chain_code=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('chain_code_hex', 'Not found'))" 2>/dev/null)
    if [ "$chain_code" != "Not found" ]; then
        echo "Chain Code (Hex): $chain_code"
    fi
    
    # Extract local party key
    local_party_key=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('local_party_key', 'Not found'))" 2>/dev/null)
    if [ "$local_party_key" != "Not found" ]; then
        echo "Local Party Key: $local_party_key"
    fi
    
    # Extract keygen committee keys count
    committee_keys_count=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); keys=data.get('keygen_committee_keys', []); print(len(keys))" 2>/dev/null)
    if [ "$committee_keys_count" != "0" ]; then
        echo "Keygen Committee Keys: $committee_keys_count keys"
        
        # Show first few keys
        echo "$decoded_content" | python3 -c "
import sys, json
data = json.load(sys.stdin)
keys = data.get('keygen_committee_keys', [])
for i, key in enumerate(keys[:5]):
    print(f'  [{i+1}] {key}')
if len(keys) > 5:
    print(f'  ... and {len(keys)-5} more keys')
" 2>/dev/null
    fi
    
    # Check for ECDSA local data
    ecdsa_data=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); print('ecdsa_local_data' in data)" 2>/dev/null)
    if [ "$ecdsa_data" = "True" ]; then
        echo
        echo "ECDSA Local Data: Present"
        
        # Check for specific ECDSA fields
        ecdsa_pub=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); ecdsa=data.get('ecdsa_local_data', {}); print(ecdsa.get('ECDSAPub', 'Not found'))" 2>/dev/null)
        if [ "$ecdsa_pub" != "Not found" ]; then
            echo "  ECDSA Public Key: $ecdsa_pub"
        fi
        
        big_xj=$(echo "$decoded_content" | python3 -c "import sys, json; data=json.load(sys.stdin); ecdsa=data.get('ecdsa_local_data', {}); print(ecdsa.get('BigXj', 'Not found'))" 2>/dev/null)
        if [ "$big_xj" != "Not found" ]; then
            echo "  BigXj: $big_xj"
        fi
    fi
fi

echo
echo "=== Parsing Complete ===" 