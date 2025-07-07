#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

nostrRelay="ws://bbw-nostr.xyz"
localTesting="true"
# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go 

echo "Starting peer 2 and 3..."

PARTY2="peer2"
PARTY3="peer3"

 echo "Start listening on peer 2..."
 "$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY2" "$nostrRelay" "$localTesting" &
PID1=$!

echo "Start listening on peer 3..." 
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY3" "$nostrRelay" "$localTesting" &
PID2=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; kill $PID2;    exit" SIGINT SIGTERM

echo "running peers. Press Ctrl+C to stop."

# Keep the script alive
wait