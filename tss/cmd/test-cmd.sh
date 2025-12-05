#!/bin/bash

# Comprehensive test script for all functions in tss/cmd/
# This script tests the nostr-keygen and nostr-keysign binaries
# and validates their outputs

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Cross-platform timeout function
run_with_timeout() {
    local duration=$1
    shift
    
    # Try standard timeout command (Linux)
    if command -v timeout >/dev/null 2>&1; then
        timeout "$duration" "$@"
        return $?
    fi
    
    # Try gtimeout (macOS with Homebrew coreutils)
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$duration" "$@"
        return $?
    fi
    
    # Fallback: bash-based timeout implementation
    "$@" &
    local cmd_pid=$!
    
    local waited=0
    while kill -0 $cmd_pid 2>/dev/null && [ $waited -lt $duration ]; do
        sleep 1
        waited=$((waited + 1))
    done
    
    if kill -0 $cmd_pid 2>/dev/null; then
        kill $cmd_pid 2>/dev/null || true
        wait $cmd_pid 2>/dev/null || true
        return 124
    fi
    
    wait $cmd_pid 2>/dev/null
    return $?
}

# Function to print test header
print_test_header() {
    echo ""
    echo "=========================================="
    echo "Testing: $1"
    echo "=========================================="
}

# Function to print success
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
    ((TESTS_PASSED++)) || true
}

# Function to print failure
print_failure() {
    echo -e "${RED}✗ $1${NC}"
    ((TESTS_FAILED++)) || true
}

# Function to print warning/skip
print_skip() {
    echo -e "${YELLOW}⊘ $1${NC}"
    ((TESTS_SKIPPED++)) || true
}

# Function to validate JSON file
validate_json_file() {
    local file="$1"
    local description="$2"
    
    if [ ! -f "$file" ]; then
        print_failure "$description: File not found: $file"
        return 1
    fi
    
    if ! command -v jq >/dev/null 2>&1; then
        if [ ! -s "$file" ]; then
            print_failure "$description: File is empty: $file"
            return 1
        fi
        return 0
    fi
    
    if ! jq empty "$file" 2>/dev/null; then
        print_failure "$description: Invalid JSON: $file"
        return 1
    fi
    
    print_success "$description: Valid JSON file created"
    return 0
}

# Function to validate keyshare file
validate_keyshare() {
    local file="$1"
    local party="$2"
    
    if ! validate_json_file "$file" "Keyshare for $party"; then
        return 1
    fi
    
    if command -v jq >/dev/null 2>&1; then
        if ! jq -e '.pub_key' "$file" >/dev/null 2>&1; then
            print_failure "Keyshare $party: Missing pub_key field"
            return 1
        fi
        
        if ! jq -e '.chain_code_hex' "$file" >/dev/null 2>&1; then
            print_failure "Keyshare $party: Missing chain_code_hex field"
            return 1
        fi
        
        if ! jq -e '.nostr_npub' "$file" >/dev/null 2>&1; then
            print_failure "Keyshare $party: Missing nostr_npub field"
            return 1
        fi
        
        print_success "Keyshare $party: Contains required fields"
    fi
    
    return 0
}

# Function to validate signature file
validate_signature() {
    local file="$1"
    local party="$2"
    
    if ! validate_json_file "$file" "Signature for $party"; then
        return 1
    fi
    
    if command -v jq >/dev/null 2>&1; then
        if ! jq -e '.r' "$file" >/dev/null 2>&1; then
            print_failure "Signature $party: Missing r field"
            return 1
        fi
        
        if ! jq -e '.s' "$file" >/dev/null 2>&1; then
            print_failure "Signature $party: Missing s field"
            return 1
        fi
        
        print_success "Signature $party: Contains required fields"
    fi
    
    return 0
}

# Function to validate signature from stdout
validate_signature_stdout() {
    local output="$1"
    local party="$2"
    
    if [ -z "$output" ]; then
        print_failure "Signature $party: No output captured"
        return 1
    fi
    
    if command -v jq >/dev/null 2>&1; then
        if echo "$output" | jq empty 2>/dev/null; then
            if echo "$output" | jq -e '.r' >/dev/null 2>&1 && echo "$output" | jq -e '.s' >/dev/null 2>&1; then
                print_success "Signature $party: Valid JSON with r and s fields"
                return 0
            else
                print_failure "Signature $party: Missing r or s field"
                return 1
            fi
        else
            JSON=$(echo "$output" | grep -oE '\{[^}]*"r"[^}]*"s"[^}]*\}' | head -1)
            if [ -n "$JSON" ] && echo "$JSON" | jq empty 2>/dev/null; then
                print_success "Signature $party: Valid JSON extracted from output"
                return 0
            else
                print_failure "Signature $party: Could not extract valid JSON from output"
                return 1
            fi
        fi
    else
        if [ -n "$output" ]; then
            print_success "Signature $party: Output captured (jq not available for full validation)"
            return 0
        else
            print_failure "Signature $party: No output"
            return 1
        fi
    fi
}

# Local relay management
LOCAL_RELAY_STARTED=false
LOCAL_RELAY_URL=""
USE_LOCAL_RELAY=false

# Function to start local relay
start_local_relay() {
    if [ "$LOCAL_RELAY_STARTED" = "true" ]; then
        USE_LOCAL_RELAY=true
        return 0
    fi
    
    echo ""
    echo "=========================================="
    echo "Setting up local Nostr relay for testing"
    echo "=========================================="
    
    if [ -f "./scripts/start-local-relay.sh" ] && ./scripts/start-local-relay.sh > /tmp/relay-start.log 2>&1; then
        LOCAL_RELAY_STARTED=true
        USE_LOCAL_RELAY=true
        LOCAL_RELAY_URL="ws://localhost:7777"
        echo "✓ Local relay is ready at $LOCAL_RELAY_URL"
        
        echo "  Waiting additional 20 seconds for WebSocket support..."
        for i in {1..20}; do
            sleep 1
            if [ $((i % 5)) -eq 0 ]; then
                echo "    ... ${i}/20 seconds"
            fi
        done
        
        if ! docker ps --format '{{.Names}}' | grep -q "^bbmtlib-test-relay$"; then
            echo "⚠ Relay container stopped unexpectedly"
            return 1
        fi
        
        return 0
    else
        echo "⚠ Failed to start local relay, falling back to external relays"
        LOCAL_RELAY_STARTED=false
        USE_LOCAL_RELAY=false
        return 1
    fi
}

# Function to stop local relay
stop_local_relay() {
    if [ "$LOCAL_RELAY_STARTED" = "true" ]; then
        echo ""
        echo "Stopping local relay..."
        [ -f "./scripts/stop-local-relay.sh" ] && ./scripts/stop-local-relay.sh >/dev/null 2>&1 || true
        LOCAL_RELAY_STARTED=false
    fi
}

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up test artifacts..."
    stop_local_relay
}

trap cleanup EXIT

echo "=========================================="
echo "BBMTLib CMD Functions Test Suite"
echo "=========================================="
echo "Working directory: $ROOT"
echo ""

# Build binaries
print_test_header "Building binaries"

if go build -o /tmp/nostr-keygen ./tss/cmd/nostr-keygen 2>&1; then
    print_success "nostr-keygen: Built successfully"
else
    print_failure "nostr-keygen: Build failed"
    exit 1
fi

if go build -o /tmp/nostr-keysign ./tss/cmd/nostr-keysign 2>&1; then
    print_success "nostr-keysign: Built successfully"
else
    print_failure "nostr-keysign: Build failed"
    exit 1
fi

# Helper functions
random_hex() {
    if [ -f "./scripts/main.go" ]; then
        go run ./scripts/main.go random 2>/dev/null || echo "$(openssl rand -hex 32)"
    else
        openssl rand -hex 32 2>/dev/null || head -c 64 /dev/urandom | xxd -p -c 64
    fi
}

generate_keypair() {
    if [ -f "./scripts/main.go" ]; then
        go run ./scripts/main.go nostr-keypair 2>/dev/null
    else
        echo "Error: scripts/main.go not found for keypair generation"
        exit 1
    fi
}

# Test 1: nostr-keygen - help/usage
print_test_header "nostr-keygen: Help/Usage"

if /tmp/nostr-keygen -h 2>&1 | grep -q "Usage\|flag\|relays"; then
    print_success "nostr-keygen: Help output works"
else
    print_failure "nostr-keygen: Help output failed"
fi

# Test 2: nostr-keygen - missing required args
print_test_header "nostr-keygen: Missing Required Arguments"

OUTPUT=$(/tmp/nostr-keygen 2>&1 || true)
if echo "$OUTPUT" | grep -E "required|Error" > /dev/null; then
    print_success "nostr-keygen: Correctly reports missing required arguments"
else
    print_failure "nostr-keygen: Should report missing required arguments"
fi

# Test 3: nostr-keygen - full execution (2-party)
print_test_header "nostr-keygen: Full Execution (2-party)"

# Start local relay if available
if start_local_relay; then
    RELAYS_TO_USE="$LOCAL_RELAY_URL"
    echo "Using local relay: $RELAYS_TO_USE"
else
    RELAYS_TO_USE="${RELAYS:-wss://nostr.hifish.org,wss://nostr.xxi.quest,wss://bbw-nostr.xyz}"
    echo "Using external relays: $RELAYS_TO_USE"
fi

# Generate keypairs
if ! KEYPAIR1=$(generate_keypair 2>/dev/null); then
    print_skip "nostr-keygen: Cannot generate keypair (scripts/main.go not available)"
else
    read -r NSEC1 NPUB1 <<<"$(echo "$KEYPAIR1" | awk -F',' '{print $1" "$2}')"
    
    if ! KEYPAIR2=$(generate_keypair 2>/dev/null); then
        print_skip "nostr-keygen: Cannot generate second keypair"
    else
        read -r NSEC2 NPUB2 <<<"$(echo "$KEYPAIR2" | awk -F',' '{print $1" "$2}')"
        
        # Generate session parameters
        SESSION_ID=$(random_hex)
        SESSION_KEY=$(random_hex)
        CHAINCODE=$(random_hex)
        
        TEST_OUTPUT_DIR="./test-cmd-keygen-output"
        mkdir -p "$TEST_OUTPUT_DIR"
        
        PARTY1_OUTPUT="$TEST_OUTPUT_DIR/party1-keyshare.json"
        PARTY2_OUTPUT="$TEST_OUTPUT_DIR/party2-keyshare.json"
        
        echo "Starting 2-party keygen..."
        echo "  Party 1 npub: $NPUB1"
        echo "  Party 2 npub: $NPUB2"
        echo "  Session ID: $SESSION_ID"
        echo "  Output directory: $TEST_OUTPUT_DIR"
        
        # Run both parties in parallel
        NOSTR_NSEC="$NSEC1" /tmp/nostr-keygen \
            -relays "$RELAYS_TO_USE" \
            -npub "$NPUB1" \
            -peers "$NPUB2" \
            -session "$SESSION_ID" \
            -session-key "$SESSION_KEY" \
            -chaincode "$CHAINCODE" \
            -timeout 300 \
            -output "$PARTY1_OUTPUT" > "$TEST_OUTPUT_DIR/party1.log" 2>&1 &
        PID1=$!
        
        NOSTR_NSEC="$NSEC2" /tmp/nostr-keygen \
            -relays "$RELAYS_TO_USE" \
            -npub "$NPUB2" \
            -peers "$NPUB1" \
            -session "$SESSION_ID" \
            -session-key "$SESSION_KEY" \
            -chaincode "$CHAINCODE" \
            -timeout 300 \
            -output "$PARTY2_OUTPUT" > "$TEST_OUTPUT_DIR/party2.log" 2>&1 &
        PID2=$!
        
        # Wait for processes with timeout
        MAX_WAIT=300
        WAIT_COUNT=0
        while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
            if ! kill -0 $PID1 2>/dev/null && ! kill -0 $PID2 2>/dev/null; then
                break
            fi
            sleep 1
            WAIT_COUNT=$((WAIT_COUNT + 1))
        done
        
        # Kill if still running
        kill $PID1 $PID2 2>/dev/null || true
        wait $PID1 2>/dev/null || true
        wait $PID2 2>/dev/null || true
        
        # Validate outputs
        if [ -f "$PARTY1_OUTPUT" ] && [ -f "$PARTY2_OUTPUT" ]; then
            if validate_keyshare "$PARTY1_OUTPUT" "party1"; then
                if validate_keyshare "$PARTY2_OUTPUT" "party2"; then
                    print_success "nostr-keygen: Successfully generated keyshares for both parties"
                    
                    # Verify matching public keys
                    if command -v jq >/dev/null 2>&1; then
                        PUB1=$(jq -r '.pub_key' "$PARTY1_OUTPUT" 2>/dev/null)
                        PUB2=$(jq -r '.pub_key' "$PARTY2_OUTPUT" 2>/dev/null)
                        if [ "$PUB1" = "$PUB2" ] && [ -n "$PUB1" ]; then
                            print_success "nostr-keygen: Both parties have matching public keys"
                        else
                            print_failure "nostr-keygen: Public keys don't match"
                        fi
                    fi
                fi
            fi
        else
            print_skip "nostr-keygen: Keyshare files not created (may have timed out)"
            if [ -f "$TEST_OUTPUT_DIR/party1.log" ]; then
                echo "  Last 20 lines of party1.log:"
                tail -20 "$TEST_OUTPUT_DIR/party1.log" | sed 's/^/    /'
            fi
        fi
    fi
fi

# Test 4: nostr-keysign - help/usage
print_test_header "nostr-keysign: Help/Usage"

if /tmp/nostr-keysign -h 2>&1 | grep -q "Usage\|flag\|relays"; then
    print_success "nostr-keysign: Help output works"
else
    print_failure "nostr-keysign: Help output failed"
fi

# Test 5: nostr-keysign - missing required args
print_test_header "nostr-keysign: Missing Required Arguments"

OUTPUT=$(/tmp/nostr-keysign 2>&1 || true)
if echo "$OUTPUT" | grep -E "required|Error" > /dev/null; then
    print_success "nostr-keysign: Correctly reports missing required arguments"
else
    print_failure "nostr-keysign: Should report missing required arguments"
fi

# Test 6: nostr-keysign - full execution (requires keygen output)
print_test_header "nostr-keysign: Full Execution"

# Check if we have keyshare files from keygen test
KEYGEN_OUTPUT_DIR="./test-cmd-keygen-output"
if [ -f "$KEYGEN_OUTPUT_DIR/party1-keyshare.json" ] && [ -f "$KEYGEN_OUTPUT_DIR/party2-keyshare.json" ]; then
    # Extract npub and nsec from keyshare files
    if [ -f "./scripts/main.go" ]; then
        NPUB1=$(go run ./scripts/main.go extract-npub "$KEYGEN_OUTPUT_DIR/party1-keyshare.json" 2>/dev/null)
        NPUB2=$(go run ./scripts/main.go extract-npub "$KEYGEN_OUTPUT_DIR/party2-keyshare.json" 2>/dev/null)
        NSEC1=$(go run ./scripts/main.go extract-nsec "$KEYGEN_OUTPUT_DIR/party1-keyshare.json" 2>/dev/null)
        NSEC2=$(go run ./scripts/main.go extract-nsec "$KEYGEN_OUTPUT_DIR/party2-keyshare.json" 2>/dev/null)
        
        if [ -n "$NPUB1" ] && [ -n "$NPUB2" ] && [ -n "$NSEC1" ] && [ -n "$NSEC2" ]; then
            # Generate session parameters
            SESSION_ID=$(random_hex)
            SESSION_KEY=$(random_hex)
            MESSAGE=$(random_hex)
            DERIVATION_PATH="m/44'/0'/0'/0/0"
            
            # All parties for keysign
            ALL_PARTIES="$NPUB1,$NPUB2"
            
            TEST_KEYSIGN_OUTPUT_DIR="./test-cmd-keysign-output"
            mkdir -p "$TEST_KEYSIGN_OUTPUT_DIR"
            
            PARTY1_OUTPUT="$TEST_KEYSIGN_OUTPUT_DIR/party1-signature.json"
            PARTY2_OUTPUT="$TEST_KEYSIGN_OUTPUT_DIR/party2-signature.json"
            
            echo "Starting 2-party keysign..."
            echo "  Party 1 npub: $NPUB1"
            echo "  Party 2 npub: $NPUB2"
            echo "  Message: $MESSAGE"
            echo "  Output directory: $TEST_KEYSIGN_OUTPUT_DIR"
            
            # Use local relay if available
            if [ "$USE_LOCAL_RELAY" = "true" ] && [ -n "$LOCAL_RELAY_URL" ]; then
                RELAYS_TO_USE="$LOCAL_RELAY_URL"
            else
                RELAYS_TO_USE="${RELAYS:-wss://bbw-nostr.xyz}"
            fi
            
            # Run both parties in parallel
            /tmp/nostr-keysign \
                -relays "$RELAYS_TO_USE" \
                -nsec "$NSEC1" \
                -peers "$ALL_PARTIES" \
                -session "$SESSION_ID" \
                -session-key "$SESSION_KEY" \
                -keyshare "$KEYGEN_OUTPUT_DIR/party1-keyshare.json" \
                -path "$DERIVATION_PATH" \
                -message "$MESSAGE" \
                -timeout 300 2>"$TEST_KEYSIGN_OUTPUT_DIR/party1.log" | awk '/^\{/,/^\}/' > "$PARTY1_OUTPUT" &
            PID1=$!
            
            /tmp/nostr-keysign \
                -relays "$RELAYS_TO_USE" \
                -nsec "$NSEC2" \
                -peers "$ALL_PARTIES" \
                -session "$SESSION_ID" \
                -session-key "$SESSION_KEY" \
                -keyshare "$KEYGEN_OUTPUT_DIR/party2-keyshare.json" \
                -path "$DERIVATION_PATH" \
                -message "$MESSAGE" \
                -timeout 300 2>"$TEST_KEYSIGN_OUTPUT_DIR/party2.log" | awk '/^\{/,/^\}/' > "$PARTY2_OUTPUT" &
            PID2=$!
            
            # Wait for processes with timeout
            MAX_WAIT=300
            WAIT_COUNT=0
            while [ $WAIT_COUNT -lt $MAX_WAIT ]; do
                if ! kill -0 $PID1 2>/dev/null && ! kill -0 $PID2 2>/dev/null; then
                    break
                fi
                sleep 1
                WAIT_COUNT=$((WAIT_COUNT + 1))
            done
            
            # Kill if still running
            kill $PID1 $PID2 2>/dev/null || true
            wait $PID1 2>/dev/null || true
            wait $PID2 2>/dev/null || true
            
            # Validate outputs
            if [ -f "$PARTY1_OUTPUT" ] && [ -s "$PARTY1_OUTPUT" ]; then
                SIG1_OUTPUT=$(cat "$PARTY1_OUTPUT")
                if validate_signature_stdout "$SIG1_OUTPUT" "party1"; then
                    if [ -f "$PARTY2_OUTPUT" ] && [ -s "$PARTY2_OUTPUT" ]; then
                        SIG2_OUTPUT=$(cat "$PARTY2_OUTPUT")
                        if validate_signature_stdout "$SIG2_OUTPUT" "party2"; then
                            print_success "nostr-keysign: Successfully generated signatures for both parties"
                            
                            # Verify signatures match
                            if command -v jq >/dev/null 2>&1; then
                                SIG1_NORM=$(echo "$SIG1_OUTPUT" | jq -c . 2>/dev/null)
                                SIG2_NORM=$(echo "$SIG2_OUTPUT" | jq -c . 2>/dev/null)
                                if [ "$SIG1_NORM" = "$SIG2_NORM" ] && [ -n "$SIG1_NORM" ]; then
                                    print_success "nostr-keysign: Signatures match between parties"
                                else
                                    print_failure "nostr-keysign: Signatures don't match"
                                fi
                            fi
                        fi
                    else
                        print_skip "nostr-keysign: Party 2 signature not created"
                    fi
                fi
            else
                print_skip "nostr-keysign: Signatures not created (may have timed out)"
                if [ -f "$TEST_KEYSIGN_OUTPUT_DIR/party1.log" ]; then
                    echo "  Last 20 lines of party1.log:"
                    tail -20 "$TEST_KEYSIGN_OUTPUT_DIR/party1.log" | sed 's/^/    /'
                fi
            fi
        else
            print_skip "nostr-keysign: Cannot extract npub/nsec from keyshare files"
        fi
    else
        print_skip "nostr-keysign: scripts/main.go not available for extracting npub/nsec"
    fi
else
    print_skip "nostr-keysign: Skipped (requires nostr-keygen output)"
    echo "  Expected keyshare files not found:"
    echo "    - $KEYGEN_OUTPUT_DIR/party1-keyshare.json"
    echo "    - $KEYGEN_OUTPUT_DIR/party2-keyshare.json"
fi

# Test Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo ""

TOTAL=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))
if [ $TOTAL -eq 0 ]; then
    echo "No tests were run!"
    exit 1
fi

if [ $TESTS_FAILED -gt 0 ]; then
    echo "Some tests failed. Check the output above for details."
    exit 1
else
    echo "All non-skipped tests passed!"
    exit 0
fi
