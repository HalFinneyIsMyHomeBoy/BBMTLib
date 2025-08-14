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

PUBLIC_KEY1=""
PUBLIC_KEY2=""

# Generate random session ID and chain code
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
MESSAGE=$("$BUILD_DIR/$BIN_NAME" random)

# Server and party details
PORT=55055
HOST="127.0.0.1"
SERVER="http://$HOST:$PORT"
<<<<<<< HEAD:scripts/keysign.sh

PARTY1="peer1"
PARTY2="peer2"
PARTIES="$PARTY1,$PARTY2"  # Participants
=======
USENOSTR="false"
NOSTRRELAY="ws://bbw-nostr.xyz"
NET_TYPE="nostr"

PARTY1="npub1p0dj3g82ff56prwnw4kkvphuv6ej25y9d2nr076795x6kescjefs7d2gqm"
PARTY2="npub132gndqvcqyrvuu2q3lwg363cadmg2l7emqd36lawr3ey068slafqvrmknn"

PARTY3="npub1rxnfxtrcfg49u3zptgc30ywf862mjfehn9x0rdu06yef8nr7phksrghwdq"

echo "Enough 2 out of 3."
PARTIES="$PARTY1,$PARTY2,$PARTY3"  # Participants
>>>>>>> origin/simplified-nostr-branch-experimental:scripts/local_sign.sh

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
echo "MESSAGE: $MESSAGE"

# load keyshares
KEYSHARE1=$(cat "$PARTY1".ks)
KEYSHARE2=$(cat "$PARTY2".ks)

# Optional: Add error checking
if [ -z "$KEYSHARE1" ] || [ -z "$KEYSHARE2" ]; then
    echo "Error: Failed to read keyshare files"
    echo "Run Keygen before..."
    exit 1
fi

# Start Relay in the background and track its PID
echo "Starting Relay..."
"$BUILD_DIR/$BIN_NAME" relay "$PORT" &
PID0=$!

DERIVATION_PATH="m/44'/0'/0'/0/0"

sleep 1

# Start keysign for both parties
echo "Starting keysign for PARTY1..."
"$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY1" "$PARTIES" "$PUBLIC_KEY2" "$PRIVATE_KEY1" "$KEYSHARE1" "$DERIVATION_PATH" "$MESSAGE" &
PID1=$!

echo "Starting keysign for PARTY2..."
"$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY2" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" "$KEYSHARE2" "$DERIVATION_PATH" "$MESSAGE" &
PID2=$!

<<<<<<< HEAD:scripts/keysign.sh
# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2; exit" SIGINT SIGTERM
=======
echo "Enough 2 out of 3."

 echo "Starting keysign for PARTY3..."
 "$BUILD_DIR/$BIN_NAME" keysign "$SERVER" "$SESSION_ID" "$PARTY3" "$PARTIES" "$PUBLIC_KEY1" "$PRIVATE_KEY2" "$KEYSHARE3" "$DERIVATION_PATH" "$MESSAGE" "$SESSION_KEY" "$NET_TYPE" &
 PID3=$!

# Handle cleanup on exit/ 2 out of 3 
trap "echo 'Stopping processes...'; kill $PID0 $PID1 $PID2 $PID3; exit" SIGINT SIGTERM
>>>>>>> origin/simplified-nostr-branch-experimental:scripts/local_sign.sh

echo "keysign processes running. Press Ctrl+C to stop."

# Keep the script alive
wait