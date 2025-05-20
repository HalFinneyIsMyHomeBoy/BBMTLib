#!/bin/bash

# Check if a .ks file is provided as an argument
if [ $# -eq 0 ]; then
    echo "Usage: $0 <ks_file>"
    exit 1
fi

# Get the input file
input_file="$1"

# Check if the file exists
if [ ! -f "$input_file" ]; then
    echo "Error: File '$input_file' not found"
    exit 1
fi

# Get the base filename without extension
base_name=$(basename "$input_file" .ks)

# Create output file name
output_file="${base_name}.nostr"

echo "Reading file: $input_file"
echo "Output will be saved to: $output_file"

# Read the base64 content and decode it
content=$(cat "$input_file" | base64 -d)
echo "Decoded content length: ${#content}"

# Extract the fields using jq and save to output file
echo "$content" | jq -r '{
    "local_nostr_pub_key": .local_nostr_pub_key,
    "local_nostr_priv_key": .local_nostr_priv_key,
    "nostr_party_pub_keys": .nostr_party_pub_keys
}' > "$output_file"

if [ $? -eq 0 ]; then
    echo "Successfully extracted nostr keys to $output_file"
    echo "File contents:"
    cat "$output_file"
else
    echo "Error: Failed to extract keys"
fi 