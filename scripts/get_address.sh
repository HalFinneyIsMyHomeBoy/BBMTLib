#!/bin/bash

# Script to parse .ks file and extract testnet3 Bitcoin address
# Based on the pattern from main.go

set -e

# Check prerequisites
if ! command -v jq &> /dev/null; then
    echo "Error: jq is not installed"
    exit 1
fi

if ! command -v base64 &> /dev/null; then
    echo "Error: base64 command not found"
    exit 1
fi

# Set peer name
peer=$1
keyshareFile="$peer.ks"
network=$2

# Check if keyshare file exists
if [ ! -f "$keyshareFile" ]; then
    echo "Error: $keyshareFile not found"
    exit 1
fi

# Read and decode keyshare
base64Content=$(cat "$keyshareFile")
jsonContent=$(echo "$base64Content" | base64 -d)

# Extract pubkey and chaincode
pubKey=$(echo "$jsonContent" | jq -r '.pub_key')
chainCode=$(echo "$jsonContent" | jq -r '.chain_code_hex')

# Set derivation path
btcPath="m/44'/0'/0'/0/0"

# Use the getAddress function from main.go
address=$(go run main.go getAddress "$pubKey" "$chainCode" "$btcPath" "$network")

# Display result
echo "$address" 	