#!/bin/bash

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

# Check if number of peers is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <number_of_peers>"
    echo "Example: $0 3"
    exit 1
fi

NUM_PEERS=$1

# Validate input
if ! [[ "$NUM_PEERS" =~ ^[0-9]+$ ]] || [ "$NUM_PEERS" -lt 1 ]; then
    echo "Error: Please provide a positive integer for number of peers"
    exit 1
fi

BIN_NAME="bbmt"
BUILD_DIR="./bin"

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Build the Go binary
echo "Building the Go binary..."
go build -o "$BUILD_DIR/$BIN_NAME" main.go

# Generate Nostr keys automatically
echo "Generating Nostr keys for all peers..."
"$BUILD_DIR/$BIN_NAME" generateNostrKeys $NUM_PEERS

# Rename the generated files to use npub as filename
echo "Renaming .nostr files to use npub as filename..."
for i in $(seq 1 $NUM_PEERS); do
    peer_file="peer$i.nostr"
    if [ -f "$peer_file" ]; then
        # Extract npub from the file
        if command -v jq &> /dev/null; then
            npub=$(jq -r '.local_nostr_pub_key' "$peer_file")
        else
            # Fallback to grep/sed if jq is not available
            npub=$(grep '"local_nostr_pub_key"' "$peer_file" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
        fi
        
        # Rename the file to use npub as filename
        new_filename="${npub}.nostr"
        mv "$peer_file" "$new_filename"
        echo "Renamed $peer_file to $new_filename"
    else
        echo "Error: $peer_file not found after generation."
        exit 1
    fi
done

# Parse the generated .nostr files to extract npubs and nsecs
echo "Parsing generated Nostr keys..."
declare -A NPUBS
declare -A NSECS
declare -A NPUB_FILES

# Find all .nostr files and extract npubs and nsecs
for nostr_file in *.nostr; do
    if [ -f "$nostr_file" ]; then
        # Extract npub and nsec using jq (if available) or grep/sed
        if command -v jq &> /dev/null; then
            npub=$(jq -r '.local_nostr_pub_key' "$nostr_file")
            nsec=$(jq -r '.local_nostr_priv_key' "$nostr_file")
        else
            # Fallback to grep/sed if jq is not available
            npub=$(grep '"local_nostr_pub_key"' "$nostr_file" | sed 's/.*"local_nostr_pub_key": *"\([^"]*\)".*/\1/')
            nsec=$(grep '"local_nostr_priv_key"' "$nostr_file" | sed 's/.*"local_nostr_priv_key": *"\([^"]*\)".*/\1/')
        fi
        
        # Store the npub and nsec with the filename as key
        NPUBS["$nostr_file"]="$npub"
        NSECS["$nostr_file"]="$nsec"
        NPUB_FILES["$nostr_file"]="$nostr_file"
        
        echo "Found $nostr_file - npub: $npub"
        echo "Found $nostr_file - nsec: $nsec"
    fi
done

# Verify we have the expected number of files
actual_count=${#NPUBS[@]}
if [ "$actual_count" -ne "$NUM_PEERS" ]; then
    echo "Error: Expected $NUM_PEERS .nostr files, but found $actual_count"
    exit 1
fi

# Create comma-separated list of all npubs for partyNpubs parameter
ALL_NPUBS=""
for nostr_file in "${!NPUBS[@]}"; do
    npub="${NPUBS[$nostr_file]}"
    if [ -z "$ALL_NPUBS" ]; then
        ALL_NPUBS="$npub"
    else
        ALL_NPUBS="$ALL_NPUBS,$npub"
    fi
done

# Generate random session ID and chain code
echo "Generating random session parameters..."
SESSION_ID=$("$BUILD_DIR/$BIN_NAME" random)
CHAIN_CODE=$("$BUILD_DIR/$BIN_NAME" random)
SESSION_KEY=$("$BUILD_DIR/$BIN_NAME" random)

echo "Generated Parameters:"
echo "SESSION ID: $SESSION_ID"
echo "CHAIN CODE: $CHAIN_CODE"
echo "SESSION KEY: $SESSION_KEY"

# Nostr configuration
NOSTR_RELAY="ws://bbw-nostr.xyz"
NET_TYPE="nostr"
LOCAL_TESTING="true"

echo ""
echo "Starting Nostr Keygen for $NUM_PEERS peers..."
echo "Using Nostr relay: $NOSTR_RELAY"
echo "Network type: $NET_TYPE"
echo "Local testing: $LOCAL_TESTING"
echo "All npubs: $ALL_NPUBS"
echo ""

# Array to store all keygen process PIDs
declare -a PIDS
declare -a OUTPUT_FILES

# Start keygen processes for all peers
peer_index=1
for nostr_file in "${!NPUBS[@]}"; do
    npub="${NPUBS[$nostr_file]}"
    nsec="${NSECS[$nostr_file]}"
    output_file="${npub}.ks"
    
    echo "Starting JoinKeygen for $nostr_file (npub: $npub)..."
    echo "Output will be saved to: $output_file"
    
    # Start the process and capture output to a temporary file while also showing it in terminal
    temp_output="/tmp/nostr_keygen_${npub}_$$.log"
    "$BUILD_DIR/$BIN_NAME" nostrKeygen "$NOSTR_RELAY" "$nsec" "$npub" "$ALL_NPUBS" "$SESSION_ID" "$SESSION_KEY" "$CHAIN_CODE" "$LOCAL_TESTING" 2>&1 | tee "$temp_output" &
    PIDS[$peer_index]=$!
    OUTPUT_FILES[$peer_index]=$temp_output
    
    # Small delay between starting peers
    if [ $peer_index -lt $NUM_PEERS ]; then
        sleep 1
    fi
    ((peer_index++))
done

# Build the kill command for all PIDs
KILL_CMD=""
for i in $(seq 1 $NUM_PEERS); do
    if [ -n "$KILL_CMD" ]; then
        KILL_CMD="$KILL_CMD ${PIDS[$i]}"
    else
        KILL_CMD="${PIDS[$i]}"
    fi
done

trap "echo 'Stopping processes...'; kill $KILL_CMD; rm -f /tmp/nostr_keygen_*_$$.log; exit" SIGINT SIGTERM

# Wait for all processes
echo "Waiting for all keygen processes to complete..."
wait

# Process the output files and extract keyshare results
echo ""
echo "Processing keygen results..."
peer_index=1
for nostr_file in "${!NPUBS[@]}"; do
    npub="${NPUBS[$nostr_file]}"
    output_file="${npub}.ks"
    temp_output="${OUTPUT_FILES[$peer_index]}"
    
    echo "Processing output for $nostr_file..."
    
    if [ -f "$temp_output" ]; then
        # Look for the "Keygen Result:" line and extract the keyshare
        keyshare_result=$(grep "Keygen Result:" "$temp_output" | sed 's/.*Keygen Result: //')
        
        if [ -n "$keyshare_result" ]; then
            echo "Found keyshare result for $nostr_file"
            echo "$keyshare_result" > "$output_file"
            echo "Keyshare saved to: $output_file"
        else
            echo "Warning: No keyshare result found for $nostr_file"
            echo "Output file contents:"
            cat "$temp_output"
        fi
        
        # Clean up temporary file
        rm -f "$temp_output"
    else
        echo "Error: Temporary output file not found for $nostr_file"
    fi
    ((peer_index++))
done

echo ""
echo "Nostr keygen completed!"
echo "Keyshare files created:"
for nostr_file in "${!NPUBS[@]}"; do
    npub="${NPUBS[$nostr_file]}"
    output_file="${npub}.ks"
    if [ -f "$output_file" ]; then
        echo "  - $output_file"
    fi
done



