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


# Get other required arguments
derivePath="m/44'/0'/0'/0/0"
receiverAddress="mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV"
amountSatoshi="1000"
estimatedFee="600"
nostrRelay="ws://bbw-nostr.xyz"


# Find the first .nostr file
nostr_file=$(find . -name "*.nostr" -type f | head -n 1)

if [ -z "$nostr_file" ]; then
    echo "No .nostr file found in current directory or subdirectories"
    exit 1
fi

echo "Found .nostr file: $nostr_file"

# Extract all npubs from nostr_party_pub_keys using jq
# This gets all values from the nostr_party_pub_keys object and joins them with commas
npubs=$(jq -r '.nostr_party_pub_keys | to_entries | map(.value) | join(",")' "$nostr_file")
echo "npubs: $npubs"
if [ $? -eq 0 ] && [ -n "$npubs" ]; then
    echo "Extracted npubs:"
    echo "$npubs"
else
    echo "Failed to extract npubs from $nostr_file"
    echo "Make sure the file contains a valid JSON with 'nostr_party_pub_keys' field"
    exit 1
fi 

# Get the local party's npub and nsec
local_npub=$(jq -r '.local_nostr_pub_key' "$nostr_file")
local_nsec=$(jq -r '.local_nostr_priv_key' "$nostr_file")

if [ -z "$local_npub" ] || [ "$local_npub" = "null" ] || [ -z "$local_nsec" ] || [ "$local_nsec" = "null" ]; then
    echo "Failed to extract local party keys from $nostr_file"
    echo "local_npub: '$local_npub'"
    echo "local_nsec: '$local_nsec'"
    exit 1
fi


# Convert comma-separated string to array
IFS=',' read -ra NPUBS <<< "$npubs"



# Generate session parameters once for all processes
sessionID=$("$BUILD_DIR/$BIN_NAME" random)
sessionKey=$("$BUILD_DIR/$BIN_NAME" random)

echo "Generated session ID: $sessionID"
echo "Generated session key: $sessionKey"

# Initialize array to store PIDs
declare -a PIDS=()
# Initialize counter
i=0
masterNpub=""
# Loop through each npub (each party)
for i in "${!NPUBS[@]}"; do
    npub="${NPUBS[$i]}"
    if [ $i -eq 0 ]; then
        masterNpub="$npub"
    fi
    
    # Find the .nostr file for this specific npub
    nostr_file=$(find . -name "$npub.nostr" -type f | head -n 1)
    echo "Looking for .nostr file: $npub.nostr"
    
    if [ -z "$nostr_file" ]; then
        echo "No .nostr file found for npub: $npub"
        echo "Expected file: $npub.nostr"
        continue  # Skip this npub and continue with the next one
    fi
    
    echo "Found .nostr file: $nostr_file"
    
    # Get the nsec from this specific .nostr file
    nsec=$(jq -r '.local_nostr_priv_key' "$nostr_file")
    
    if [ -z "$nsec" ] || [ "$nsec" = "null" ]; then
        echo "Failed to extract nsec from $nostr_file"
        echo "nsec value: '$nsec'"
        echo "Make sure the file contains a valid 'local_nostr_priv_key' field"
        continue  # Skip this npub and continue with the next one
    fi


    "$BUILD_DIR/$BIN_NAME" nostrSpend "$npub" "$nsec" "$npubs" "$nostrRelay" "$sessionID" "$sessionKey" "$receiverAddress" "$derivePath" "$amountSatoshi" "$estimatedFee" "$i" "$masterNpub" &
    PIDS[$i]=$!
    sleep 1

    i=$((i+1))
done

# Set up trap to kill all processes when script is interrupted
trap 'echo "Stopping all processes..."; for pid in "${PIDS[@]}"; do if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then echo "Killing PID: $pid"; kill "$pid"; fi; done; exit' SIGINT SIGTERM

echo "All processes started. PIDs: ${PIDS[*]}"
echo "Press Ctrl+C to stop all processes"

# Wait for all processes to complete
for pid in "${PIDS[@]}"; do
    if [ -n "$pid" ]; then
        wait "$pid"
    fi
done
