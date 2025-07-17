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

# Generate Nostr keys automatically
echo "Generating Nostr keys for all peers..."
"$BUILD_DIR/$BIN_NAME" generateNostrKeys

# Parse the generated .nostr files to extract npubs and nsecs
echo "Parsing generated Nostr keys..."
declare -A NPUBS
declare -A NSECS

for peer in peer1 peer2 peer3; do
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
ALL_NPUBS="${NPUBS[peer1]},${NPUBS[peer2]},${NPUBS[peer3]}"

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
echo "Starting Nostr Keygen for all peers..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Network type: $NET_TYPE"
echo "Local testing: $LOCAL_TESTING"
echo "All npubs: $ALL_NPUBS"
echo ""

# Array to store all Nostr listener PIDs

# Array to store all keygen process PIDs
#KEYGEN_PIDS=()


#sleep 3
# Wait for Nostr listeners to start

# Run JoinKeygen for peer1 using the bbmt binary with actual Nostr keys
echo "Starting JoinKeygen for peer1..."
"$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "${NSECS[peer1]}" "${NPUBS[peer1]}" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" &
PID1=$!

sleep 3

echo "Starting JoinKeygen for peer2..."
"$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "${NSECS[peer2]}" "${NPUBS[peer2]}" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" &
PID2=$!

sleep 1

echo "Starting JoinKeygen for peer3..."
"$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "${NSECS[peer3]}" "${NPUBS[peer3]}" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" &
PID3=$!

trap "echo 'Stopping processes...'; kill $PID1 $PID2 $PID3; exit" SIGINT SIGTERM



