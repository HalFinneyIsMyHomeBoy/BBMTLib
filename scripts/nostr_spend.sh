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

# Set peer name
localParty="peer1"

# Check if required .nostr file exists
if [ ! -f "$localParty.nostr" ]; then
    print_warning "$localParty.nostr file not found. Generating Nostr keys first..."
    
    # Run the generateNostrKeys mode to create the required files
    print_status "Generating Nostr keys for all peers..."
    go run main.go generateNostrKeys
    
    if [ ! -f "$localParty.nostr" ]; then
        print_error "Failed to generate $localParty.nostr file"
        exit 1
    fi
    print_success "Nostr keys generated successfully"
fi

# Check if keyshare file exists (required for BTC sending)
if [ ! -f "$localParty.ks" ]; then
    print_error "$localParty.ks file not found. You need to run keygen first."
    print_status "Please run: ./run_nostr_keygen.sh"
    exit 1
fi

# Build the Go application
print_status "Building Go application..."
go build -o bbmtlib main.go

if [ $? -ne 0 ]; then
    print_error "Failed to build the application"
    exit 1
fi
print_success "Application built successfully"

# Run the nostrSendBTC mode
print_status "Starting nostrSendBTC process..."
print_status "This will initiate a BTC send transaction using Nostr for $localParty"
print_status "Default settings:"
print_status "  - Receiver: mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV (testnet)"
print_status "  - Amount: 1000 satoshis"
print_status "  - Fee: 600 satoshis"
print_status "  - Derivation path: m/44'/0'/0'/0/0"

./bbmtlib nostrSendBTC

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
    print_status "Check the transaction details above"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 