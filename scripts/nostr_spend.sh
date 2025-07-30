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
# or: ./nostr_spend.sh npub1abc... npub1def... npub1ghi...
if [ "$#" -lt 1 ]; then
    print_error "Usage: $0 peer1 [peer2 ...]"
    print_error "   or: $0 npub1abc... [npub1def... ...]"
    exit 1
fi

peers=("$@")

# Validate required files for each peer
for peer in "${peers[@]}"; do
    # Check if the peer argument is already an npub (starts with npub)
    if [[ "$peer" == npub* ]]; then
        # It's already an npub, use it directly
        if [ ! -f "$peer.nostr" ]; then
            print_error "$peer.nostr file not found. Please generate Nostr keys for $peer."
            exit 1
        fi
        if [ ! -f "$peer.ks" ]; then
            print_error "$peer.ks file not found. You need to run keygen for $peer."
            exit 1
        fi
        print_success "Found required files for $peer"
    else
        # It's a peer name, check for .nostr and .ks files
        if [ ! -f "$peer.nostr" ]; then
            print_error "$peer.nostr file not found. Please generate Nostr keys for $peer."
            exit 1
        fi
        if [ ! -f "$peer.ks" ]; then
            print_error "$peer.ks file not found. You need to run keygen for $peer."
            exit 1
        fi
        print_success "Found required files for $peer"
    fi
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
# Extract ALL Nostr public keys from .nostr files
nostr_pub_keys=()
for peer in "${peers[@]}"; do
    if command -v jq &> /dev/null; then
        # Extract all party public keys from the .nostr file
        # First, get the local_nostr_pub_key
        local_npub=$(jq -r '.local_nostr_pub_key' "$peer.nostr" 2>/dev/null)
        if [ "$local_npub" != "null" ] && [ -n "$local_npub" ]; then
            nostr_pub_keys+=("$local_npub")
            print_status "Extracted local npub for $peer: $local_npub"
        else
            print_error "Failed to extract local npub from $peer.nostr"
            exit 1
        fi
        
        # Extract all party public keys from nostr_party_pub_keys
        # Handle both map and array formats
        party_keys=$(jq -r '.nostr_party_pub_keys | if type == "object" then to_entries | .[].value else .[] end' "$peer.nostr" 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$party_keys" ]; then
            while IFS= read -r npub; do
                if [ -n "$npub" ] && [ "$npub" != "null" ]; then
                    # Check if this npub is already in our list
                    if [[ ! " ${nostr_pub_keys[@]} " =~ " ${npub} " ]]; then
                        nostr_pub_keys+=("$npub")
                        print_status "Extracted party npub: $npub"
                    fi
                fi
            done <<< "$party_keys"
        else
            print_warning "No party public keys found in $peer.nostr"
        fi
    else
        print_error "jq is required to parse .nostr files. Please install jq."
        exit 1
    fi
done

# Join the npub values with commas
parties=$(IFS=','; echo "${nostr_pub_keys[*]}")
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
cleanup() {
    echo 'Stopping nostrSendBTC processes...'
    for pid in "${PIDS[@]}"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
        fi
    done
    exit
}

trap cleanup SIGINT SIGTERM

echo "nostrSendBTC processes running for peers: ${peers[*]}. Press Ctrl+C to stop."

wait

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
    print_status "Check the transaction details above"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 