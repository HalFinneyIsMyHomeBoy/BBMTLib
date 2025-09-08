#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go


# Check if number of peers is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <number_of_peers>"
    echo "Example: $0 3"
    exit 1
fi

NUM_PEERS=$1

# Validate input
if ! [[ "$NUM_PEERS" =~ ^[0-9]+$ ]] || [ "$NUM_PEERS" -lt 1 ]; then
    echo "Error: Please provide a positive integer for number of peers"
    exit 1
fi

# Generate Nostr keys automatically
echo "Generating Nostr keys for all peers..."
"$BUILD_DIR/$BIN_NAME" generateNostrKeys $NUM_PEERS


# Rename generated files from peerX.nostr to npub.nostr
echo "Renaming generated files to use npub names..."
for nostr_file in peer*.nostr; do
    if [ -f "$nostr_file" ]; then
        echo "Processing $nostr_file..."
        
        # Extract the local_nostr_pub_key (npub) from the file
        if command -v jq &> /dev/null; then
            # Use jq to extract the npub
            npub=$(jq -r '.local_nostr_pub_key' "$nostr_file")
        else
            # Fallback to grep/sed if jq is not available
            npub=$(grep '"local_nostr_pub_key"' "$nostr_file" | grep -o 'npub[^"]*')
        fi
        
        if [ -n "$npub" ] && [ "$npub" != "null" ]; then
            new_filename="${npub}.nostr"
            echo "Renaming $nostr_file to $new_filename"
            mv "$nostr_file" "$new_filename"
        else
            echo "Warning: Could not extract npub from $nostr_file"
        fi
    fi
done

# Load all .nostr files and extract party pub keys
echo "Loading .nostr files..."
ALL_PARTY_NPUBS=()

for nostr_file in *.nostr; do
    if [ -f "$nostr_file" ]; then
        echo "Processing $nostr_file..."
        
        # Extract nostr_party_pub_keys array using jq (if available) or grep/sed
        if command -v jq &> /dev/null; then
            # Use jq to extract the array and convert to newline-separated values
            party_npubs=$(jq -r '.nostr_party_pub_keys[]' "$nostr_file")
        else
            # Fallback to grep/sed if jq is not available
            party_npubs=$(grep -A 10 '"nostr_party_pub_keys"' "$nostr_file" | grep -o 'npub[^"]*' | tr -d ',' | tr -d ' ')
        fi
        
        # Add each npub to our array
        while IFS= read -r npub; do
            if [ -n "$npub" ] && [ "$npub" != "null" ]; then
                ALL_PARTY_NPUBS+=("$npub")
            fi
        done <<< "$party_npubs"
    fi
done