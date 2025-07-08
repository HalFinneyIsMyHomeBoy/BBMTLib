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

# Check if .nostr files exist for all peers
echo "Checking for existing Nostr key files..."
for peer in peer1 peer2 peer3; do
    if [ ! -f "$peer.nostr" ]; then
        echo "Error: $peer.nostr file not found. Please run 'generateNostrKeys' first."
        echo "Usage: go run main.go generateNostrKeys"
        exit 1
    fi
    echo "Found $peer.nostr"
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
PARTIES="peer1,peer2,peer3"

echo ""
echo "Starting Nostr Keygen for peer1..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Network type: $NET_TYPE"
echo "Local testing: $LOCAL_TESTING"
echo "Parties: $PARTIES"
echo ""



# Array to store all Nostr listener PIDs
NOSTR_PIDS=()

# Start Nostr listener in background for peer1
echo "Starting Nostr listener for peer1..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages peer1 "$NOSTR_RELAY" "$LOCAL_TESTING" &
NOSTR_PIDS+=($!)
sleep 1

echo "Starting Nostr listener for peer2..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages peer2 "$NOSTR_RELAY" "$LOCAL_TESTING" &
NOSTR_PIDS+=($!)
sleep 1

echo "Starting Nostr listener for peer3..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages peer3 "$NOSTR_RELAY" "$LOCAL_TESTING" &
NOSTR_PIDS+=($!)

sleep 3
# Wait for Nostr listeners to start

# Function to cleanup Nostr listeners
cleanup() {
    echo "Cleaning up Nostr listeners..."
    for pid in "${NOSTR_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            echo "Killed Nostr listener PID: $pid"
        fi
    done
    exit 0
}

# Set trap to cleanup on script exit
trap cleanup EXIT INT TERM

# Run JoinKeygen for peer1 using the bbmt binary
echo "Starting JoinKeygen for peer1..."
"$BUILD_DIR/$BIN_NAME" keygen "" "$SESSION_ID" "$CHAIN_CODE" peer1 "$PARTIES" "" "" "$SESSION_KEY" "$NET_TYPE" "true"

sleep 12

echo "Starting JoinKeygen for peer2..."
"$BUILD_DIR/$BIN_NAME" keygen "" "$SESSION_ID" "$CHAIN_CODE" peer2 "$PARTIES" "" "" "$SESSION_KEY" "$NET_TYPE" "false"

sleep 6

echo "Starting JoinKeygen for peer3..."
"$BUILD_DIR/$BIN_NAME" keygen "" "$SESSION_ID" "$CHAIN_CODE" peer3 "$PARTIES" "" "" "$SESSION_KEY" "$NET_TYPE" "false"

# Wait for all keygen processes to complete
wait

echo ""
echo "Nostr Keygen completed for peer1!"
echo "Check peer1.ks for the generated keyshare."
echo ""
echo "To run keygen for other peers, you would need to:"
echo "1. Run this script in separate terminals for each peer"
echo "2. Or modify the script to run all peers simultaneously"
echo ""
echo "For multi-peer keygen, you can also use the regular 'keygen' mode"
echo "with a local relay server." 