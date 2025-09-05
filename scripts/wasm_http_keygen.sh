#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" ../cli/main.go


# Generate random session ID and chain code
#$("$BUILD_DIR/$BIN_NAME" random-seed)
SESSION_ID=f37ef33ae5620e93b6495b0f2b7ece781a8478abd978df1ceab4a999e0d9a6c8
SESSION_KEY=f37ef33ae5620e93b6495b0f2b7ece781a8478abd978df1ceab4a999e0d9a6c8
CHAIN_CODE=f37ef33ae5620e93b6495b0f2b7ece781a8478abd978df1ceab4a999e0d9a6c8

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"

PARTY1="peer1"
PARTY2="peer2"
PARTY3="peer3"
PARTIES="$PARTY1,$PARTY2,$PARTY3"  # Participants

# Start Relay in the background and track its PID
"$BUILD_DIR/$BIN_NAME" http-relay "$PORT" &
PID0=$!

# Start Keygen for both parties
echo "Starting Keygen for PARTY1..."
VERBOSE1=""
"$BUILD_DIR/$BIN_NAME" http-keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY1" "$PARTIES" "" "" "$SESSION_KEY" "$PARTY1.ppm" "save" "somepass" "$VERBOSE1" &
PID1=$!

echo "Starting Keygen for PARTY2..."
VERBOSE2=""
"$BUILD_DIR/$BIN_NAME" http-keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY2" "$PARTIES" "" "" "$SESSION_KEY" "$PARTY2.ppm" "save" "somepass" "$VERBOSE2" &
PID2=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2; exit" SIGINT SIGTERM

echo "Keygen processes running. Press Ctrl+C to stop."

# Keep the script alive
wait