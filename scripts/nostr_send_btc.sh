#!/bin/bash

# Script to call main.go with nostrSendBTC mode
# This script sets up the environment and calls the nostrSendBTC function

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

# Usage: ./nostr_send_btc.sh <peer> <receiverAddress> <amountSatoshi> <estimatedFee>
if [ "$#" -ne 4 ]; then
    print_error "Usage: $0 <peer> <receiverAddress> <amountSatoshi> <estimatedFee>"
    print_error "Example: $0 peer1 'mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV' 1000 600"
    exit 1
fi

peer="$1"
receiverAddress="$2"
amountSatoshi="$3"
estimatedFee="$4"

# Check if jq is available for parsing JSON
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq to parse JSON files."
    exit 1
fi

# Load nostr party pub keys from the .nostr file
if [ ! -f "$peer.nostr" ]; then
    print_error "$peer.nostr file not found. Please generate Nostr keys for $peer."
    exit 1
fi

# Extract party pub keys from the .nostr file and convert to comma-separated string
parties=$(jq -r '.nostr_party_pub_keys | join(",")' "$peer.nostr")
if [ "$parties" = "null" ] || [ -z "$parties" ]; then
    print_error "Failed to extract nostr_party_pub_keys from $peer.nostr"
    exit 1
fi

derivePath="m/44'/0'/0'/0/0"

print_status "Peer: $peer"
print_status "Parties: $parties (loaded from $peer.nostr)"
print_status "Derive Path: $derivePath (hardcoded)"
print_status "Receiver Address: $receiverAddress"
print_status "Amount (satoshi): $amountSatoshi"
print_status "Estimated Fee (satoshi): $estimatedFee"

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

# Build the Go application
print_status "Building Go application..."
BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
print_status "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

if [ $? -ne 0 ]; then
    print_error "Failed to build the application"
    exit 1
fi
print_success "Application built successfully"

# Call nostrSendBTC
print_status "Calling nostrSendBTC..."
"$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "$peer"

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 