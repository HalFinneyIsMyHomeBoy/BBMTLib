#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

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

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
print_status "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

# Check if .nostr files exist for all peers
print_status "Checking for existing Nostr key files..."
for peer in peer1 peer2 peer3; do
    if [ ! -f "$peer.nostr" ]; then
        print_error "$peer.nostr file not found. Please run 'generateNostrKeys' first."
        print_info "Usage: go run main.go generateNostrKeys"
        exit 1
    fi
    print_success "Found $peer.nostr"
done

# Generate random session parameters
print_status "Generating random session parameters..."
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
SESSION_KEY=$("$BUILD_DIR/$BIN_NAME" random)
CHAINCODE=$("$BUILD_DIR/$BIN_NAME" random)

print_success "Generated Parameters:"
echo "SESSION ID: $SESSION_ID"
echo "SESSION KEY: $SESSION_KEY"
echo "CHAINCODE: $CHAINCODE"

# Nostr configuration
NOSTR_RELAY="ws://bbw-nostr.xyz"

# Extract Nostr keys from peer1.nostr (this will be the local peer)
print_status "Extracting Nostr keys from peer1.nostr..."
if ! command -v jq &> /dev/null; then
    print_error "jq is required but not installed. Please install jq to parse JSON files."
    exit 1
fi

# Read the peer1.nostr file and extract the required keys
NOSTR_CONFIG=$(cat peer1.nostr)

# Extract local private key (nsec1)
NSEC1=$(echo "$NOSTR_CONFIG" | jq -r '.local_nostr_priv_key')
if [ "$NSEC1" = "null" ] || [ -z "$NSEC1" ]; then
    print_error "Failed to extract local_nostr_priv_key from peer1.nostr"
    exit 1
fi

# Extract local public key (npub1)
NPUB1=$(echo "$NOSTR_CONFIG" | jq -r '.local_nostr_pub_key')
if [ "$NPUB1" = "null" ] || [ -z "$NPUB1" ]; then
    print_error "Failed to extract local_nostr_pub_key from peer1.nostr"
    exit 1
fi

# Extract all party public keys and create comma-separated list
NPUBS=$(echo "$NOSTR_CONFIG" | jq -r '.nostr_party_pub_keys | to_entries | map(.value) | join(",")')
if [ "$NPUBS" = "null" ] || [ -z "$NPUBS" ]; then
    print_error "Failed to extract nostr_party_pub_keys from peer1.nostr"
    exit 1
fi

print_success "Extracted Nostr keys:"
echo "Local Private Key (nsec1): $NSEC1"
echo "Local Public Key (npub1): $NPUB1"
echo "All Party Public Keys (npubs): $NPUBS"
echo ""

print_status "Starting NostrMpcTssSetup..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Session ID: $SESSION_ID"
echo "Session Key: $SESSION_KEY"
echo "Chaincode: $CHAINCODE"
echo ""

# Call the NostrMpcTssSetup function
print_status "Executing NostrMpcTssSetup..."
"$BUILD_DIR/$BIN_NAME" nostrMpcTssSetup "$NOSTR_RELAY" "$NSEC1" "$NPUB1" "$NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAINCODE"

if [ $? -eq 0 ]; then
    print_success "NostrMpcTssSetup completed successfully!"
else
    print_error "NostrMpcTssSetup failed with exit code $?"
    exit 1
fi 