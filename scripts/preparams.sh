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

# Array to store all keygen process PIDs
PIDS=()

# Write to file optional
PPM="ppm.json"

# Start the process directly - output will be visible in terminal
"$BUILD_DIR/$BIN_NAME" preparams "$PPM" &
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
echo "Waiting for all keygen processes to complete..."
wait

echo "All keygen processes completed!"