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

# Remove duplicates and sort to find the highest (master) npub
echo "Finding master npub..."
UNIQUE_NPUBS=($(printf '%s\n' "${ALL_PARTY_NPUBS[@]}" | sort -u))
MASTER_NPUB=$(printf '%s\n' "${UNIQUE_NPUBS[@]}" | sort | tail -1)

echo "All party npubs: ${UNIQUE_NPUBS[*]}"
echo "Master npub (highest lexicographically): $MASTER_NPUB"

# Find the other two npubs (non-master)
OTHER_NPUBS=()
for npub in "${UNIQUE_NPUBS[@]}"; do
    if [ "$npub" != "$MASTER_NPUB" ]; then
        OTHER_NPUBS+=("$npub")
    fi
done

echo "Other npubs for TSS keygen: ${OTHER_NPUBS[*]}"

# Generate random session parameters
echo "Generating random session parameters..."
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
CHAIN_CODE=$("$BUILD_DIR/$BIN_NAME" random)
SESSION_KEY=$("$BUILD_DIR/$BIN_NAME" random)

echo "Generated Parameters:"
echo "SESSION ID: $SESSION_ID"
echo "CHAIN CODE: $CHAIN_CODE"
echo "SESSION KEY: $SESSION_KEY"

# Nostr configuration
NOSTR_RELAY="ws://bbw-nostr.xyz"
VERBOSE="true"

echo ""
echo "Starting TSS NostrKeygen for non-master npubs..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Master npub: $MASTER_NPUB"
echo ""

# Create comma-separated list of all npubs for partyNpubs parameter
ALL_NPUBS=$(printf '%s,' "${UNIQUE_NPUBS[@]}" | sed 's/,$//')

# Array to store all TSS keygen process PIDs
TSS_PIDS=()

# Launch TSS keygen for each of the other two npubs
for npub in "${OTHER_NPUBS[@]}"; do
    # Find the corresponding .nostr file for this npub
    nostr_file="${npub}.nostr"
    
    if [ -f "$nostr_file" ]; then
        # Extract local nsec and npub from the file
        if command -v jq &> /dev/null; then
            local_nsec=$(jq -r '.local_nostr_priv_key' "$nostr_file")
            local_npub=$(jq -r '.local_nostr_pub_key' "$nostr_file")
        else
            # Fallback to grep/sed if jq is not available
            local_nsec=$(grep '"local_nostr_priv_key"' "$nostr_file" | sed 's/.*"local_nostr_priv_key": *"\([^"]*\)".*/\1/')
            local_npub=$(grep '"local_nostr_pub_key"' "$nostr_file" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
        fi
        
        echo "Starting TSS NostrKeygen for $npub..."
        echo "Local npub: $local_npub"
        echo "Local nsec: $local_nsec"
        echo "Party npubs: $ALL_NPUBS"
        echo ""
        
        # Launch TSS keygen with the specified parameters
        # NostrKeygen(nostrRelay, localNsec, localNpub, partyNpubs, chainCode, sessionKey, sessionID, verbose)
        "$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "$local_nsec" "$local_npub" "$ALL_NPUBS" "$CHAIN_CODE" "$SESSION_KEY" "$SESSION_ID" "$VERBOSE" &
        TSS_PIDS+=($!)
        
        # Small delay between starting processes
        sleep 1
    else
        echo "Warning: $nostr_file not found for npub $npub"
    fi
done

# Build the kill command for all TSS PIDs
KILL_CMD=""
for pid in "${TSS_PIDS[@]}"; do
    if [ -n "$KILL_CMD" ]; then
        KILL_CMD="$KILL_CMD $pid"
    else
        KILL_CMD="$pid"
    fi
done

# Set up signal handler to kill all processes on Ctrl+C
trap "echo 'Stopping TSS keygen processes...'; kill $KILL_CMD 2>/dev/null; echo 'All processes stopped.'; exit" SIGINT SIGTERM

echo "TSS keygen processes started for non-master npubs!"
echo "Master npub ($MASTER_NPUB) is excluded from TSS keygen as requested."
echo "Press Ctrl+C to stop all processes."

# Wait for all processes
echo "Waiting for all TSS keygen processes to complete..."
wait

echo "All TSS keygen processes completed!"
