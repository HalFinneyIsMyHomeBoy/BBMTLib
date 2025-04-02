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
KEYPAIR3=$("$BUILD_DIR/$BIN_NAME" keypair)

NOSTR_KEYPAIR1=$("$BUILD_DIR/$BIN_NAME" keypair)
NOSTR_KEYPAIR2=$("$BUILD_DIR/$BIN_NAME" keypair)
NOSTR_KEYPAIR3=$("$BUILD_DIR/$BIN_NAME" keypair)

NOSTR_PRIVATE_KEY1=$(echo "$NOSTR_KEYPAIR1" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY2=$(echo "$NOSTR_KEYPAIR2" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY3=$(echo "$NOSTR_KEYPAIR3" | jq -r '.privateKey')

NOSTR_PUBLIC_KEY1=$(echo "$NOSTR_KEYPAIR1" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY2=$(echo "$NOSTR_KEYPAIR2" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY3=$(echo "$NOSTR_KEYPAIR3" | jq -r '.publicKey')

PRIVATE_KEY1=$(echo "$KEYPAIR1" | jq -r '.privateKey')
PRIVATE_KEY2=$(echo "$KEYPAIR2" | jq -r '.privateKey')
PRIVATE_KEY3=$(echo "$KEYPAIR3" | jq -r '.privateKey')

PUBLIC_KEY1=$(echo "$KEYPAIR1" | jq -r '.publicKey')
PUBLIC_KEY2=$(echo "$KEYPAIR2" | jq -r '.publicKey')
PUBLIC_KEY3=$(echo "$KEYPAIR3" | jq -r '.publicKey')

# Generate random session ID and chain code
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
CHAIN_CODE=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"
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
    "nostr_pubkeys": {
      ($p1): $k1,
      ($p2): $k2,
      ($p3): $k3
    }
  }')


echo "Generated Parameters:"

echo "PARTY1: $PARTY1"
echo "PARTY2: $PARTY2"
echo "PARTY3: $PARTY3"
echo "\n"
echo "KEYPAIR1: $KEYPAIR1"
echo "KEYPAIR2: $KEYPAIR2"
echo "KEYPAIR3: $KEYPAIR3"

echo "$NOSTR_PARTY_PUBKEYS"
#echo "$NOSTR_PARTY_MAP" | jq -r '.peer1'

echo "SESSION ID: $SESSION_ID"
echo "CHAIN CODE: $CHAIN_CODE"

# Start Relay in the background and track its PID
echo "Starting Relay..."
"$BUILD_DIR/$BIN_NAME" relay "$PORT" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY1" "$NOSTR_PRIVATE_KEY1" &
PID0=$!

SESSION_KEY=$("$BUILD_DIR/$BIN_NAME" random)


# Start Keygen for both parties
echo "Starting Keygen for PARTY1..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY1" "$PARTIES" "$PUBLIC_KEY2" "$PRIVATE_KEY1" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY1" "$NOSTR_PRIVATE_KEY1" "$NOSTR_PARTY_PUBKEYS"&
PID1=$!

echo "Starting Keygen for PARTY2..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY2" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY2" "$NOSTR_PRIVATE_KEY2" "$NOSTR_PARTY_PUBKEYS"&
PID2=$!

echo "Starting Keygen for PARTY3..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY3" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY3" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY3" "$NOSTR_PRIVATE_KEY3" "$NOSTR_PARTY_PUBKEYS"&
PID3=$!

# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2; exit" SIGINT SIGTERM

echo "Keygen processes running. Press Ctrl+C to stop."

# Keep the script alive
wait