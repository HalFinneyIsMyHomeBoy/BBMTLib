#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

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

# Parse the generated .nostr files to extract npubs and nsecs
echo "Parsing generated Nostr keys..."
declare -A NPUBS
declare -A NSECS

# Generate peer names dynamically
for i in $(seq 1 $NUM_PEERS); do
    peer="peer$i"
    if [ ! -f "$peer.nostr" ]; then
        echo "Error: $peer.nostr file not found after generation."
        exit 1
    fi
    
    # Extract npub and nsec using jq (if available) or grep/sed
    if command -v jq &> /dev/null; then
        NPUBS[$peer]=$(jq -r '.local_nostr_pub_key' "$peer.nostr")
        NSECS[$peer]=$(jq -r '.local_nostr_priv_key' "$peer.nostr")
    else
        # Fallback to grep/sed if jq is not available
        NPUBS[$peer]=$(grep '"local_nostr_pub_key"' "$peer.nostr" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
        NSECS[$peer]=$(grep '"local_nostr_priv_key"' "$peer.nostr" | sed 's/.*"local_nostr_priv_key": *"\([^"]*\)".*/\1/')
    fi
    
    echo "Found $peer - npub: ${NPUBS[$peer]}"
    echo "Found $peer - nsec: ${NSECS[$peer]}"
done

# Create comma-separated list of all npubs for partyNpubs parameter
ALL_NPUBS=""
for i in $(seq 1 $NUM_PEERS); do
    peer="peer$i"
    if [ -z "$ALL_NPUBS" ]; then
        ALL_NPUBS="${NPUBS[$peer]}"
    else
        ALL_NPUBS="$ALL_NPUBS,${NPUBS[$peer]}"
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
declare -a PIDS

# Start keygen processes for all peers
for i in $(seq 1 $NUM_PEERS); do
    peer="peer$i"
    echo "Starting JoinKeygen for $peer..."
    "$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "${NSECS[$peer]}" "${NPUBS[$peer]}" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" &
    PIDS[$i]=$!
    
    # Small delay between starting peers
    if [ $i -lt $NUM_PEERS ]; then
        sleep 1
    fi
done

# Build the kill command for all PIDs
KILL_CMD=""
for i in $(seq 1 $NUM_PEERS); do
    if [ -n "$KILL_CMD" ]; then
        KILL_CMD="$KILL_CMD ${PIDS[$i]}"
    else
        KILL_CMD="${PIDS[$i]}"
    fi
done

trap "echo 'Stopping processes...'; kill $KILL_CMD; exit" SIGINT SIGTERM

# Wait for all processes
wait



