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


PARTY2="peer2"
PARTY3="peer3"
PARTY4="peer4"
 echo "Start listening on peer 2..."
 "$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY2" &
PID1=$!

echo "Start listening on peer 3..."
"$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY3" &    
PID2=$!

echo "Start listening on peer 4..." 
"$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY4" &
PID3=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; kill $PID2; kill $PID3; exit" SIGINT SIGTERM

echo "running peer processes running. Press Ctrl+C to stop."

# Keep the script alive
wait