#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

nostrRelay="ws://bbw-nostr.xyz"
localTesting="true"

# Usage: ./nostr_run_peers.sh peer2 peer3 ...
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 peer2 [peer3 ...]"
    exit 1
fi

peers=("$@")

# Validate required files for each peer
for peer in "${peers[@]}"; do
    if [ ! -f "$peer.nostr" ]; then
        echo "[ERROR] $peer.nostr file not found. Please generate Nostr keys for $peer."
        exit 1
    fi
    echo "[INFO] Found required files for $peer"
done

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go 

# Start ListenNostrMessages for each peer in background
PIDS=()
for peer in "${peers[@]}"; do
    echo "Start listening on $peer..."
    nsec=$(jq -r '.local_nostr_priv_key' "$peer.nostr")
    npub=$(jq -r '.local_nostr_pub_key' "$peer.nostr")
    echo "nsec: $nsec"
    echo "npub: $npub"
    "$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$npub" "$nsec" "$nostrRelay" &
    PIDS+=("$!")
done

# Handle cleanup on exit
cleanup() {
    echo 'Stopping processes...'
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "running peers: ${peers[*]}. Press Ctrl+C to stop."

# Keep the script alive
wait