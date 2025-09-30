#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

# Run nodns and generate login
echo "Starting nodns service..."
./nodns &
NODNS_PID=$!

# Wait a moment for nodns to start
sleep 2

echo "Generating nodns-cli login..."
NSEC=$(nodns-cli login generate)
echo "Generated nsec: $NSEC"

echo "Logging in with generated nsec..."
./nodns-cli login $NSEC

# Prompt user for IP address
echo ""
read -p "Enter IP address for DNS record: " IP_ADDRESS

# Validate IP address input
if [ -z "$IP_ADDRESS" ]; then
    echo "Error: IP address cannot be empty"
    exit 1
fi

echo "Adding DNS record for IP address: $IP_ADDRESS"
./nodns-cli records add a @ $IP_ADDRESS

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

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

# Generate Nostr keys automatically
echo "Generating Nostr keys for all peers..."
"$BUILD_DIR/$BIN_NAME" generateNostrKeys $NUM_PEERS

# Rename the generated files to use npub as filename
echo "Renaming .nostr files to use npub as filename..."
for i in $(seq 1 $NUM_PEERS); do
    peer_file="peer$i.nostr"
    if [ -f "$peer_file" ]; then
        # Extract npub from the file
        if command -v jq &> /dev/null; then
            npub=$(jq -r '.local_nostr_pub_key' "$peer_file")
        else
            # Fallback to grep/sed if jq is not available
            npub=$(grep '"local_nostr_pub_key"' "$peer_file" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
        fi
        
        # Rename the file to use npub as filename
        new_filename="${npub}.nostr"
        mv "$peer_file" "$new_filename"
        echo "Renamed $peer_file to $new_filename"
    else
        echo "Error: $peer_file not found after generation."
        exit 1
    fi
done

# Parse the generated .nostr files to extract npubs and nsecs
echo "Parsing generated Nostr keys..."

# Use arrays instead of associative arrays for better compatibility
NPUB_FILES=()
NPUBS=()
NSECS=()

# Find all .nostr files and extract npubs and nsecs
for nostr_file in *.nostr; do
    if [ -f "$nostr_file" ]; then
        # Extract npub and nsec using jq (if available) or grep/sed
        if command -v jq &> /dev/null; then
            npub=$(jq -r '.local_nostr_pub_key' "$nostr_file")
            nsec=$(jq -r '.local_nostr_priv_key' "$nostr_file")
        else
            # Fallback to grep/sed if jq is not available
            npub=$(grep '"local_nostr_pub_key"' "$nostr_file" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
            nsec=$(grep '"local_nostr_priv_key"' "$nostr_file" | sed 's/.*"local_nostr_priv_key": *"\([^"]*\)".*/\1/')
        fi
        
        # Store the data in parallel arrays
        NPUB_FILES+=("$nostr_file")
        NPUBS+=("$npub")
        NSECS+=("$nsec")
        
        echo "Found $nostr_file - npub: $npub"
        echo "Found $nostr_file - nsec: $nsec"
    fi
done

# Verify we have the expected number of files
actual_count=${#NPUB_FILES[@]}
if [ "$actual_count" -ne "$NUM_PEERS" ]; then
    echo "Error: Expected $NUM_PEERS .nostr files, but found $actual_count"
    exit 1
fi

# Create comma-separated list of all npubs for partyNpubs parameter
ALL_NPUBS=""
for i in $(seq 0 $((actual_count - 1))); do
    npub="${NPUBS[$i]}"
    if [ -z "$ALL_NPUBS" ]; then
        ALL_NPUBS="$npub"
    else
        ALL_NPUBS="$ALL_NPUBS,$npub"
    fi
done

# Generate random session ID and chain code
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
NET_TYPE="nostr"
LOCAL_TESTING="true"

echo ""
echo "Starting Nostr Keygen for $NUM_PEERS peers..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Network type: $NET_TYPE"
echo "Local testing: $LOCAL_TESTING"
echo "All npubs: $ALL_NPUBS"
echo ""

# Array to store all keygen process PIDs
PIDS=()

# Start keygen processes for all peers
for i in $(seq 0 $((actual_count - 1))); do
    nostr_file="${NPUB_FILES[$i]}"
    npub="${NPUBS[$i]}"
    nsec="${NSECS[$i]}"
    output_file="${npub}.ks"
    
    echo "Starting JoinKeygen for $nostr_file (npub: $npub)..."
    echo "Output will be saved to: $output_file"
    
    # Start the process directly - output will be visible in terminal
    "$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "$nsec" "$npub" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" &
    PIDS+=($!)
    
    # Small delay between starting peers
    if [ $i -lt $((actual_count - 1)) ]; then
        sleep 1
    fi
done

# Build the kill command for all PIDs
KILL_CMD=""
for pid in "${PIDS[@]}"; do
    if [ -n "$KILL_CMD" ]; then
        KILL_CMD="$KILL_CMD $pid"
    else
        KILL_CMD="$pid"
    fi
done

trap "echo 'Stopping processes...'; kill $KILL_CMD; kill $NODNS_PID 2>/dev/null; exit" SIGINT SIGTERM

# Wait for all processes
echo "Waiting for all keygen processes to complete..."
wait

echo "All keygen processes completed!"

# Clean up nodns process
echo "Stopping nodns service..."
kill $NODNS_PID 2>/dev/null || true


