#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

nostrRelay="wss://bbw-nostr.xyz"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go 


PARTY2="peer2"
PARTY3="peer3"






 echo "Start listening on peer 2..."
 "$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY2" "$nostrRelay" &
PID1=$!

echo "Start listening on peer 3..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY3" "$nostrRelay" &    
PID2=$!


# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; kill $PID2;  exit" SIGINT SIGTERM

echo "running peers. Press Ctrl+C to stop."

# Keep the script alive
wait