#!/bin/bash

# Function to print a section header
print_header() {
    echo "==========================================="
    echo "$1"
    echo "==========================================="
}

# Function to print a field with proper formatting
print_field() {
    local field_name="$1"
    local field_value="$2"
    printf "%-25s: %s\n" "$field_name" "$field_value"
}

# Process each .ks file in the current directory
for ks_file in *.ks; do
    if [ ! -f "$ks_file" ]; then
        echo "No .ks files found in the current directory"
        exit 1
    fi

    print_header "Contents of $ks_file"
    echo

    # Decode base64 and format JSON, then print to stdout
    cat "$ks_file" | base64 -d | jq '.'
    echo
done 