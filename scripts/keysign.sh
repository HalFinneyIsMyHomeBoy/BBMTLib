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
KEYPAIR1=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR2=$("$BUILD_DIR/$BIN_NAME" keypair)

PRIVATE_KEY1=$(echo "$KEYPAIR1" | jq -r '.privateKey')
PRIVATE_KEY2=$(echo "$KEYPAIR2" | jq -r '.privateKey')

PUBLIC_KEY1=$(echo "$KEYPAIR1" | jq -r '.publicKey')
PUBLIC_KEY2=$(echo "$KEYPAIR2" | jq -r '.publicKey')

# Generate random session ID and chain code
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
MESSAGE=$("$BUILD_DIR/$BIN_NAME" random)
SESSION_KEY=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"
USENOSTR="true"
NOSTRRELAY="ws://bbw-nostr.xyz"
NET_TYPE=""

PARTY1="peer1"
PARTY2="peer2"
PARTY3="peer3"
PARTIES="$PARTY1,$PARTY2,$PARTY3"  # Participants

echo "Generated Parameters:"

echo "PARTY1: $PARTY1"
echo "PARTY2: $PARTY2"
echo "PARTY3: $PARTY3"

echo "KEYPAIR1: $KEYPAIR1"
echo "KEYPAIR2: $KEYPAIR2"

echo "PRIVATE_KEY1: $PRIVATE_KEY1"
echo "PRIVATE_KEY2: $PRIVATE_KEY2"

echo "PUBLIC_KEY1: $PUBLIC_KEY1"
echo "PUBLIC_KEY2: $PUBLIC_KEY2"

echo "SESSION ID: $SESSION_ID"
echo "MESSAGE: $MESSAGE"

# load keyshares
KEYSHARE1=$(cat "$PARTY1".ks)
KEYSHARE2=$(cat "$PARTY2".ks)
KEYSHARE3=$(cat "$PARTY3".ks)

# Optional: Add error checking
if [ -z "$KEYSHARE1" ] || [ -z "$KEYSHARE2" ]; then
    echo "Error: Failed to read keyshare files"
    echo "Run Keygen before..."
    exit 1
fi

if [ "$USENOSTR" = "true" ]; then
    echo "Starting Nostr Relay..."
    NET_TYPE="nostr"
else
    echo "Starting Standard LAN Relay..."
    NET_TYPE=""
    "$BUILD_DIR/$BIN_NAME" relay "$PORT" "$NET_TYPE" & PID0=$!
fi


DERIVATION_PATH="m/44'/0'/0'/0/0"

sleep 1
#"$BUILD_DIR/$BIN_NAME" test "$PARTY1" & PID1=$!
# Start keysign for both parties
echo "Starting keysign for PARTY1..."
"$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY1" "$PARTIES" "$PUBLIC_KEY2" "$PRIVATE_KEY1" "$KEYSHARE1" "$DERIVATION_PATH" "$MESSAGE" "$SESSION_KEY" "$NET_TYPE" &
PID1=$!

echo "Starting keysign for PARTY2..."
"$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY2" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" "$KEYSHARE2" "$DERIVATION_PATH" "$MESSAGE" "$SESSION_KEY" "$NET_TYPE" &
PID2=$!

echo "Starting keysign for PARTY2..."
"$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY3" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" "$KEYSHARE3" "$DERIVATION_PATH" "$MESSAGE" "$SESSION_KEY" "$NET_TYPE" &
PID3=$!

# Handle cleanup on exit/ 2 out of 3 
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2 $PID3; exit" SIGINT SIGTERM

echo "keysign processes running. Press Ctrl+C to stop."

# Keep the script alive
wait