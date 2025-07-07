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

# Build the Go application
print_status "Building Go application..."
BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

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

# Default values for arguments
# trying 2 out of 3
parties="peer1,peer2,peer3"
session="$(go run main.go random)"
sessionKey="$(go run main.go random)"
derivePath="m/44'/0'/0'/0/0"
receiverAddress="mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV"
amountSatoshi="1000"
estimatedFee="600"
peer="$localParty"
net_type="nostr"
localTesting=true

"$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$session" "$sessionKey" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "peer1" "$net_type" "$localTesting" &
PID1=$!

#"$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$session" "$sessionKey" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "peer2" "$net_type" &
#PID2=$!

#"$BUILD_DIR/$BIN_NAME" nostrSendBTC "$parties" "$session" "$sessionKey" "$derivePath" "$receiverAddress" "$amountSatoshi" "$estimatedFee" "peer3" "$net_type" &
#PID3=$!

# Trap to kill background processes on exit
trap "echo 'Stopping nostrSendBTC processes...'; kill $PID1 2>/dev/null; exit" SIGINT SIGTERM

echo "nostrSendBTC processes running. Press Ctrl+C to stop."

wait

if [ $? -eq 0 ]; then
    print_success "nostrSendBTC completed successfully!"
    print_status "Check the transaction details above"
else
    print_error "nostrSendBTC failed"
    exit 1
fi 