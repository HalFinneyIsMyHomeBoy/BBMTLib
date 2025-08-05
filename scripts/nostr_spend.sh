#!/bin/bash

# Script to run the nostrSendBTC mode of the BBMTLib TSS application
# This script automatically extracts npub keys from .nostr files and launches the BTC sending process

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

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    print_error "main.go not found. Please run this script from the scripts directory."
    exit 1
fi

# Usage: ./nostr_spend.sh peer1
if [ "$#" -ne 1 ]; then
    print_error "Usage: $0 <peer>"
    print_error "Example: $0 peer1"
    exit 1
fi

peer="$1"

# Validate required files for the peer
if [ ! -f "$peer.nostr" ]; then
    print_error "$peer.nostr file not found. Please generate Nostr keys for $peer."
    exit 1
fi
if [ ! -f "$peer.ks" ]; then
    print_error "$peer.ks file not found. You need to run keygen for $peer."
    exit 1
fi
print_success "Found required files for $peer"

# Extract all npub keys from the .nostr file
print_status "Extracting npub keys from $peer.nostr..."
parties=$(jq -r '.nostr_party_pub_keys | to_entries[] | .value' "$peer.nostr" | tr '\n' ',' | sed 's/,$//')

if [ -z "$parties" ]; then
    print_error "No npub keys found in $peer.nostr"
    exit 1
fi

print_success "Found parties: $parties"

# Build the Go application
print_status "Building Go application..."
BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
go build -o "$BUILD_DIR/$BIN_NAME" main.go

if [ $? -ne 0 ]; then
    print_error "Failed to build the application"
    exit 1
fi
print_success "Application built successfully"

# Default values for arguments
derivePath="m/44'/0'/0'/0/0"
receiverAddress="mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV"
amountSatoshi="1000"
estimatedFee="600"
net_type="nostr"
localTesting="true"

print_status "Starting nostrSendBTC for $peer..."
print_status "parties: $parties"
print_status "derivePath: $derivePath"
print_status "receiverAddress: $receiverAddress"
print_status "amountSatoshi: $amountSatoshi"
print_status "estimatedFee: $estimatedFee"
print_status "net_type: $net_type"

# Run nostrSendBTC
"$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "$peer"

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
    print_status "Check the transaction details above"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 