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
CHAIN_CODE=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"
<<<<<<< HEAD:scripts/keygen.sh

PARTY1="peer1"
PARTY2="peer2"
PARTIES="$PARTY1,$PARTY2"  # Participants
=======

USENOSTR="false"
NOSTRRELAY="ws://bbw-nostr.xyz"

PARTY1="peer1"
PARTY2="peer2"
PARTY3="peer3"

PARTIES="$PARTY1,$PARTY2,$PARTY3"  # Participants

# Create JSON object mapping parties to their Nostr public keys
NOSTR_PARTY_PUBKEYS=$(jq -n \
  --arg p1 "$PARTY1" --arg k1 "$NOSTR_PUBLIC_KEY1" \
  --arg p2 "$PARTY2" --arg k2 "$NOSTR_PUBLIC_KEY2" \
  --arg p3 "$PARTY3" --arg k3 "$NOSTR_PUBLIC_KEY3" \
  '{
    "nostr_party_pub_keys": {
      ($p1): $k1,
      ($p2): $k2,
      ($p3): $k3
    }
  }')

>>>>>>> origin/simplified-nostr-branch-experimental:scripts/local_keygen.sh

echo "Generated Parameters:"

echo "PARTY1: $PARTY1"
echo "PARTY2: $PARTY2"

echo "KEYPAIR1: $KEYPAIR1"
echo "KEYPAIR2: $KEYPAIR2"

echo "PRIVATE_KEY1: $PRIVATE_KEY1"
echo "PRIVATE_KEY2: $PRIVATE_KEY2"

echo "PUBLIC_KEY1: $PUBLIC_KEY1"
echo "PUBLIC_KEY2: $PUBLIC_KEY2"

echo "SESSION ID: $SESSION_ID"
echo "CHAIN CODE: $CHAIN_CODE"

# Start Relay in the background and track its PID
echo "Starting Relay..."
"$BUILD_DIR/$BIN_NAME" relay "$PORT" &
PID0=$!

# Start Keygen for both parties
echo "Starting Keygen for PARTY1..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY1" "$PARTIES" "$PUBLIC_KEY2" "$PRIVATE_KEY1" &
PID1=$!

echo "Starting Keygen for PARTY2..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY2" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" &
PID2=$!

<<<<<<< HEAD:scripts/keygen.sh
=======
echo "Starting Keygen for PARTY3..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY3" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY3" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY3" "$NOSTR_PRIVATE_KEY3" "$NOSTR_PARTY_PUBKEYS"&
PID3=$!


>>>>>>> origin/simplified-nostr-branch-experimental:scripts/local_keygen.sh
# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2 $PID3; exit" SIGINT SIGTERM

echo "Keygen processes running. Press Ctrl+C to stop."

# Keep the script alive
wait