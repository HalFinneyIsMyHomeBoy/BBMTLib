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


# Generate random session ID and chain code
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
MESSAGE=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"

PARTY2="peer2"
PARTY3="peer3"

 echo "Start listening on peer 2..."
 "$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY2" &
PID1=$!

echo "Start listening on peer 3..."
"$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY3" &    
PID2=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; kill $PID2; exit" SIGINT SIGTERM

echo "running peer processes running. Press Ctrl+C to stop."

# Keep the script alive
wait