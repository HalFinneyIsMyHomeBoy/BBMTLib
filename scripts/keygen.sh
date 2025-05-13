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
KEYPAIR4=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR5=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR6=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR7=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR8=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR9=$("$BUILD_DIR/$BIN_NAME" keypair)
KEYPAIR10=$("$BUILD_DIR/$BIN_NAME" keypair)






NOSTR_KEYPAIR1=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR2=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR3=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR4=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR5=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR6=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR7=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR8=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR9=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)
NOSTR_KEYPAIR10=$("$BUILD_DIR/$BIN_NAME" nostrKeypair)

NOSTR_PRIVATE_KEY1=$(echo "$NOSTR_KEYPAIR1" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY2=$(echo "$NOSTR_KEYPAIR2" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY3=$(echo "$NOSTR_KEYPAIR3" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY4=$(echo "$NOSTR_KEYPAIR4" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY5=$(echo "$NOSTR_KEYPAIR5" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY6=$(echo "$NOSTR_KEYPAIR6" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY7=$(echo "$NOSTR_KEYPAIR7" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY8=$(echo "$NOSTR_KEYPAIR8" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY9=$(echo "$NOSTR_KEYPAIR9" | jq -r '.privateKey')
NOSTR_PRIVATE_KEY10=$(echo "$NOSTR_KEYPAIR10" | jq -r '.privateKey')
NOSTR_PUBLIC_KEY1=$(echo "$NOSTR_KEYPAIR1" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY2=$(echo "$NOSTR_KEYPAIR2" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY3=$(echo "$NOSTR_KEYPAIR3" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY4=$(echo "$NOSTR_KEYPAIR4" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY5=$(echo "$NOSTR_KEYPAIR5" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY6=$(echo "$NOSTR_KEYPAIR6" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY7=$(echo "$NOSTR_KEYPAIR7" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY8=$(echo "$NOSTR_KEYPAIR8" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY9=$(echo "$NOSTR_KEYPAIR9" | jq -r '.publicKey')
NOSTR_PUBLIC_KEY10=$(echo "$NOSTR_KEYPAIR10" | jq -r '.publicKey')
PRIVATE_KEY1=$(echo "$KEYPAIR1" | jq -r '.privateKey')
PRIVATE_KEY2=$(echo "$KEYPAIR2" | jq -r '.privateKey')
PRIVATE_KEY3=$(echo "$KEYPAIR3" | jq -r '.privateKey')
PRIVATE_KEY4=$(echo "$KEYPAIR4" | jq -r '.privateKey')
PRIVATE_KEY5=$(echo "$KEYPAIR5" | jq -r '.privateKey')
PRIVATE_KEY6=$(echo "$KEYPAIR6" | jq -r '.privateKey')
PRIVATE_KEY7=$(echo "$KEYPAIR7" | jq -r '.privateKey')
PRIVATE_KEY8=$(echo "$KEYPAIR8" | jq -r '.privateKey')
PRIVATE_KEY9=$(echo "$KEYPAIR9" | jq -r '.privateKey')
PRIVATE_KEY10=$(echo "$KEYPAIR10" | jq -r '.privateKey')
PUBLIC_KEY1=$(echo "$KEYPAIR1" | jq -r '.publicKey')
PUBLIC_KEY2=$(echo "$KEYPAIR2" | jq -r '.publicKey')
PUBLIC_KEY3=$(echo "$KEYPAIR3" | jq -r '.publicKey')
PUBLIC_KEY4=$(echo "$KEYPAIR4" | jq -r '.publicKey')
PUBLIC_KEY5=$(echo "$KEYPAIR5" | jq -r '.publicKey')
PUBLIC_KEY6=$(echo "$KEYPAIR6" | jq -r '.publicKey')
PUBLIC_KEY7=$(echo "$KEYPAIR7" | jq -r '.publicKey')
PUBLIC_KEY8=$(echo "$KEYPAIR8" | jq -r '.publicKey')
PUBLIC_KEY9=$(echo "$KEYPAIR9" | jq -r '.publicKey')
PUBLIC_KEY10=$(echo "$KEYPAIR10" | jq -r '.publicKey')
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
PARTY4="peer4"
PARTY5="peer5"
PARTY6="peer6"
PARTY7="peer7"
PARTY8="peer8"
PARTY9="peer9"
PARTY10="peer10"
PARTIES="$PARTY1,$PARTY2,$PARTY3,$PARTY4,$PARTY5,$PARTY6,$PARTY7,$PARTY8,$PARTY9,$PARTY10"  # Participants


# Create JSON object mapping parties to their Nostr public keys
NOSTR_PARTY_PUBKEYS=$(jq -n \
  --arg p1 "$PARTY1" --arg k1 "$NOSTR_PUBLIC_KEY1" \
  --arg p2 "$PARTY2" --arg k2 "$NOSTR_PUBLIC_KEY2" \
  --arg p3 "$PARTY3" --arg k3 "$NOSTR_PUBLIC_KEY3" \
  --arg p4 "$PARTY4" --arg k4 "$NOSTR_PUBLIC_KEY4" \
  --arg p5 "$PARTY5" --arg k5 "$NOSTR_PUBLIC_KEY5" \
  --arg p6 "$PARTY6" --arg k6 "$NOSTR_PUBLIC_KEY6" \
  --arg p7 "$PARTY7" --arg k7 "$NOSTR_PUBLIC_KEY7" \
  --arg p8 "$PARTY8" --arg k8 "$NOSTR_PUBLIC_KEY8" \
  --arg p9 "$PARTY9" --arg k9 "$NOSTR_PUBLIC_KEY9" \
  --arg p10 "$PARTY10" --arg k10 "$NOSTR_PUBLIC_KEY10" \
  '{
    "nostr_party_pub_keys": {
      ($p1): $k1,
      ($p2): $k2,
      ($p3): $k3,
      ($p4): $k4,
      ($p5): $k5,
      ($p6): $k6,
      ($p7): $k7,
      ($p8): $k8,
      ($p9): $k9,
      ($p10): $k10,
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

echo "Starting Keygen for PARTY4..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY4" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY4" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY4" "$NOSTR_PRIVATE_KEY4" "$NOSTR_PARTY_PUBKEYS"&
PID4=$!


echo "Starting Keygen for PARTY5..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY5" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY5" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY5" "$NOSTR_PRIVATE_KEY5" "$NOSTR_PARTY_PUBKEYS"&
PID5=$!

echo "Starting Keygen for PARTY6..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY6" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY6" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY6" "$NOSTR_PRIVATE_KEY6" "$NOSTR_PARTY_PUBKEYS"&
PID6=$! 

echo "Starting Keygen for PARTY7..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY7" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY7" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY7" "$NOSTR_PRIVATE_KEY7" "$NOSTR_PARTY_PUBKEYS"&
PID7=$!

echo "Starting Keygen for PARTY8..."  
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY8" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY8" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY8" "$NOSTR_PRIVATE_KEY8" "$NOSTR_PARTY_PUBKEYS"&
PID8=$!

echo "Starting Keygen for PARTY9..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY9" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY9" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY9" "$NOSTR_PRIVATE_KEY9" "$NOSTR_PARTY_PUBKEYS"&
PID9=$! 

echo "Starting Keygen for PARTY10..."
"$BUILD_DIR/$BIN_NAME" keygen "$SERVER" "$SESSION_ID" "$CHAIN_CODE" "$PARTY10" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY10" "$SESSION_KEY" "$USENOSTR" "$NOSTRRELAY" "$NOSTR_PUBLIC_KEY10" "$NOSTR_PRIVATE_KEY10" "$NOSTR_PARTY_PUBKEYS"&
PID10=$!









# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2 $PID3 $PID4 $PID5 $PID6 $PID7 $PID8 $PID9 $PID10; exit" SIGINT SIGTERM

echo "Keygen processes running. Press Ctrl+C to stop."

# Keep the script alive
wait