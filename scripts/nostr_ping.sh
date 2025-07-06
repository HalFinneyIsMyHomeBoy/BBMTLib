#!/bin/bash

# Nostr Ping Script
# This script runs the nostrPing functionality from the main.go file

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
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

# Function to show usage
show_usage() {
    echo "Usage: $0 <localParty> <recipientNpub>"
    echo ""
    echo "Arguments:"
    echo "  localParty     The local party name (e.g., peer1, peer2, peer3)"
    echo "  recipientNpub  The recipient's Nostr public key in npub format"
    echo ""
    echo "Examples:"
    echo "  $0 peer1 npub1abc123def456..."
    echo "  $0 peer2 npub1xyz789uvw012..."
    echo ""
    echo "Prerequisites:"
    echo "  - The .nostr file for the local party must exist"
    echo "  - Go must be installed and accessible"
    echo "  - The main.go file must be in the same directory"
}

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    print_error "main.go not found in current directory"
    print_info "Please run this script from the scripts/ directory"
    exit 1
fi

# Check arguments
if [ $# -ne 2 ]; then
    print_error "Invalid number of arguments"
    echo ""
    show_usage
    exit 1
fi

LOCAL_PARTY="$1"
RECIPIENT_NPUB="$2"

# Validate local party argument
if [ -z "$LOCAL_PARTY" ]; then
    print_error "Local party cannot be empty"
    exit 1
fi

# Validate recipient npub argument
if [ -z "$RECIPIENT_NPUB" ]; then
    print_error "Recipient npub cannot be empty"
    exit 1
fi

# Check if npub format is valid (starts with npub1)
if [[ ! "$RECIPIENT_NPUB" =~ ^npub1 ]]; then
    print_warning "Recipient npub should start with 'npub1'"
fi

# Check if .nostr file exists for the local party
NOSTR_FILE="${LOCAL_PARTY}.nostr"
if [ ! -f "$NOSTR_FILE" ]; then
    print_error "Nostr keys file not found: $NOSTR_FILE"
    print_info "Please ensure the .nostr file exists for $LOCAL_PARTY"
    print_info "You can generate it using: go run main.go generateNostrKeys"
    exit 1
fi

print_info "Starting Nostr ping from $LOCAL_PARTY to $RECIPIENT_NPUB"
print_info "Using Nostr relay: ws://bbw-nostr.xyz"

# Run the nostrPing command
print_info "Executing nostrPing..."
go run main.go nostrPing "$LOCAL_PARTY" "$RECIPIENT_NPUB"

