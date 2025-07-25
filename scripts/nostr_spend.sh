#!/bin/bash

# Script to run the nostrSendBTC mode of the BBMTLib TSS application
# This script sets up the environment and launches the BTC sending process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    print_error "main.go not found. Please run this script from the scripts directory."
    exit 1
fi

# Usage: ./nostr_spend.sh peer1 peer2 peer3 ...
if [ "$#" -lt 1 ]; then
    print_error "Usage: $0 peer1 [peer2 ...]"
    exit 1
fi

peers=("$@")

# Validate required files for each peer
for peer in "${peers[@]}"; do
    if [ ! -f "$peer.nostr" ]; then
        print_error "$peer.nostr file not found. Please generate Nostr keys for $peer."
        exit 1
    fi
    if [ ! -f "$peer.ks" ]; then
        print_error "$peer.ks file not found. You need to run keygen for $peer."
        exit 1
    fi
    print_success "Found required files for $peer"
done

# Build the Go application
print_status "Building Go application..."
BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

if [ $? -ne 0 ]; then
    print_error "Failed to build the application"
    exit 1
fi
print_success "Application built successfully"

# Default values for arguments
parties="${peers[*]}"
parties="${parties// /,}"
derivePath="m/44'/0'/0'/0/0"
receiverAddress="mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV"
amountSatoshi="1000"
estimatedFee="600"
net_type="nostr"
localTesting="true"

print_status "parties: $parties"
print_status "derivePath: $derivePath"
print_status "receiverAddress: $receiverAddress"
print_status "amountSatoshi: $amountSatoshi"
print_status "estimatedFee: $estimatedFee"
print_status "net_type: $net_type"

# Start nostrSendBTC for each peer in background
PIDS=()
for peer in "${peers[@]}"; do
    print_status "Starting nostrSendBTC for $peer..."
    "$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "$peer" &
    PIDS+=("$!")
done

# Trap to kill all background processes on exit
trap "echo 'Stopping nostrSendBTC processes...'; kill ${PIDS[@]} 2>/dev/null; exit" SIGINT SIGTERM

echo "nostrSendBTC processes running for peers: ${peers[*]}. Press Ctrl+C to stop."

wait

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
    print_status "Check the transaction details above"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 