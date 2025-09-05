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

# Array to store all keysign process PIDs
PIDS=()

NOSTR_RELAY=ws://bbw-nostr.xyz

NSEC1=nsec18jnh37qs39mtpgzc4w6rckdtndt7jd36rhapqwalhfqke3dh8u3qgyyz8z
NPUB1=npub1ry0n9qvavgveanjr25meq46hf57axt4qhnvgfl68sn5haddyf6wqpr79uv

NSEC2=nsec1qucmxuagznf33744e6xfy6yxt3g7rfcv4pecr42aswmzynfvdl9quu7v2m
NPUB2=npub1vj4gakv4epy2yzxd4ck0hnejwyuefzedlylrqswmnfktc4gsl3zsplxuth

NSEC3=nsec1lz3rkp7cg450aghanh9fm5c7q0n5wnf44v96rk9yxxacmhctl4yss5trua
NPUB3=npub1pqxtrp3sj5mcdv98j9vjt52h50z4tjrqmvxclrlfa9338ljtds7s807vw4

ALL_NPUBS="$NPUB1,$NPUB2,$NPUB3"

sessionID=$("$BUILD_DIR/$BIN_NAME" random-seed)
sessionKey=$("$BUILD_DIR/$BIN_NAME" random-seed)
message=$("$BUILD_DIR/$BIN_NAME" random-seed)
derivePath="m/44'/0'/0'/0/0"

# read the key share files
KS1=$(cat "$NPUB1.ks")
KS2=$(cat "$NPUB2.ks")
KS3=$(cat "$NPUB3.ks") 

# Start the process directly - output will be visible in terminal
# verbose for more logs
V1="verbose"
"$BUILD_DIR/$BIN_NAME" nostr-keysign "$NOSTR_RELAY" "$NSEC1" "$NPUB1" "$ALL_NPUBS" "$KS1" "$sessionID" "$sessionKey" "$message" "$derivePath" "somepass" "$V1" &
PIDS+=($!)

V2="verbose"
"$BUILD_DIR/$BIN_NAME" nostr-keysign "$NOSTR_RELAY" "$NSEC2" "$NPUB2" "$ALL_NPUBS" "$KS2" "$sessionID" "$sessionKey" "$message" "$derivePath" "somepass" "$V2" &
PIDS+=($!)

V3="verbose"
"$BUILD_DIR/$BIN_NAME" nostr-keysign "$NOSTR_RELAY" "$NSEC3" "$NPUB3" "$ALL_NPUBS" "$KS3" "$sessionID" "$sessionKey" "$message" "$derivePath" "somepass" "$V3" &
PIDS+=($!)

# Build the kill command for all PIDs
KILL_CMD=""
for pid in "${PIDS[@]}"; do
    if [ -n "$KILL_CMD" ]; then
        KILL_CMD="$KILL_CMD $pid"
    else
        KILL_CMD="$pid"
    fi
done

trap "echo 'Stopping processes...'; kill $KILL_CMD; exit" SIGINT SIGTERM

# Wait for all processes
echo "Waiting for all keysign processes to complete..."
wait

echo "All keysign processes completed!"