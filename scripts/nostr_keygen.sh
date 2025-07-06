#!/bin/bash

# Script to run the nostrKeygen mode of the BBMTLib TSS application
# This script sets up the environment and launches the key generation process

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

# Check if required .nostr file exists for peer1
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

# Check if peer1.json file exists (required for keygen)
if [ ! -f "$localParty.json" ]; then
    print_warning "$localParty.json file not found. Creating empty PPM file..."
    echo '{}' > "$localParty.json"
    print_success "Created $localParty.json file"
fi

# Build the Go application
print_status "Building Go application..."
go build -o bbmtlib main.go

if [ $? -ne 0 ]; then
    print_error "Failed to build the application"
    exit 1
fi
print_success "Application built successfully"

# Run the nostrKeygen mode
print_status "Starting nostrKeygen process..."
print_status "This will generate a new keypair using Nostr for peer1"

./bbmtlib nostrKeygen

if [ $? -eq 0 ]; then
    print_success "nostrKeygen completed successfully!"
    print_status "Check the generated files:"
    ls -la peer1.* 2>/dev/null || print_warning "No peer1 files found"
else
    print_error "nostrKeygen failed"
    exit 1
fi 