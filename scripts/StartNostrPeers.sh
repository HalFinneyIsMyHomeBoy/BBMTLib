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
PARTY4="peer4"
PARTY5="peer5"
PARTY6="peer6"
PARTY7="peer7"
PARTY8="peer8"
PARTY9="peer9"
PARTY10="peer10"






 echo "Start listening on peer 2..."
 "$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY2" "$nostrRelay" &
PID1=$!

echo "Start listening on peer 3..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY3" "$nostrRelay" &    
PID2=$!

echo "Start listening on peer 4..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY4" "$nostrRelay" &
PID3=$!

echo "Start listening on peer 5..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY5" "$nostrRelay" &
PID4=$!

echo "Start listening on peer 6..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY6" "$nostrRelay" &
PID5=$!

echo "Start listening on peer 7..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY7" "$nostrRelay" &
PID6=$!

echo "Start listening on peer 8..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY8" "$nostrRelay" &
PID7=$!

echo "Start listening on peer 9..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY9" "$nostrRelay" &
PID8=$!

echo "Start listening on peer 10..."
"$BUILD_DIR/$BIN_NAME" ListenNostrMessages "$PARTY10" "$nostrRelay" &
PID9=$!


# Handle cleanup on exit
trap "echo 'Stopping processes...'; kill $PID1; kill $PID2; kill $PID3; kill $PID4; kill $PID5; kill $PID6; kill $PID7; kill $PID8; kill $PID9; exit" SIGINT SIGTERM

echo "running peers. Press Ctrl+C to stop."

# Keep the script alive
wait