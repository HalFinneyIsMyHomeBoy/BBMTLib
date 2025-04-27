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

# Generate key pairs
#KEYPAIR1=$("$BUILD_DIR/$BIN_NAME" keypair)
#KEYPAIR2=$("$BUILD_DIR/$BIN_NAME" keypair)

#PRIVATE_KEY1=$(echo "$KEYPAIR1" | jq -r '.privateKey')
#PRIVATE_KEY2=$(echo "$KEYPAIR2" | jq -r '.privateKey')

#PUBLIC_KEY1=$(echo "$KEYPAIR1" | jq -r '.publicKey')
#PUBLIC_KEY2=$(echo "$KEYPAIR2" | jq -r '.publicKey')

# Generate random session ID and chain code
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
MESSAGE=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"

PARTY2="peer2"

 echo "Starting running peer..."
 "$BUILD_DIR/$BIN_NAME" MPCSentBTCPeer "$PARTY2" &
PID1=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; exit" SIGINT SIGTERM

echo "running peer processes running. Press Ctrl+C to stop."

# Keep the script alive
wait