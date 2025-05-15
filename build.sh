#!/bin/bash

set -e

# Default to Android
TARGET="android"

# Check CLI args
if [[ "$1" == "--iphone" ]]; then
  TARGET="ios"
elif [[ "$1" == "--android" ]]; then
  TARGET="android"
fi

# Setup
export GOFLAGS="-mod=mod"
go mod tidy
go get golang.org/x/mobile/bind
gomobile init

# Build
if [[ "$TARGET" == "android" ]]; then
  echo "Building gomobile TSS Android lib..."
  gomobile bind -v -target=android -androidapi 21 github.com/BoldBitcoinWallet/BBMTLib/tss
else
  echo "Building gomobile TSS iOS + macOS lib..."
  gomobile bind -v -target=ios,macos,iossimulator -tags=ios,macos,iossimulator github.com/BoldBitcoinWallet/BBMTLib/tss
fi