# BBMTLib Command-Line Tools

This directory contains command-line tools for performing Multi-Party Computation (MPC) Threshold Signature Scheme (TSS) operations using Nostr as the transport layer.

## Quick Reference

### nostr-keygen
```bash
nostr-keygen \
  -relays "wss://relay1.com,wss://relay2.com" \
  -npub "npub1..." \
  -peers "npub1other1...,npub1other2..." \
  -session "session_id" \
  -session-key "session_key_hex" \
  -chaincode "chaincode_hex" \
  -output keyshare.json
```

### nostr-keysign
```bash
nostr-keysign \
  -relays "wss://relay1.com" \
  -nsec "nsec1..." \
  -peers "npub1self...,npub1other..." \
  -session "session_id" \
  -session-key "session_key_hex" \
  -keyshare keyshare.json \
  -message "message to sign"
```

## Overview

The cmd tools provide standalone binaries for:
- **nostr-keygen**: Generate shared keys using MPC across multiple parties
- **nostr-keysign**: Sign messages using previously generated shared keys

Both tools use Nostr relays for communication between parties, enabling distributed key generation and signing without requiring direct peer-to-peer connections.

## Building

### Build Both Binaries

```bash
# From the project root
go build -o bin/nostr-keygen ./tss/cmd/nostr-keygen
go build -o bin/nostr-keysign ./tss/cmd/nostr-keysign
```

### Build Individual Binaries

```bash
# Build nostr-keygen only
go build -o bin/nostr-keygen ./tss/cmd/nostr-keygen

# Build nostr-keysign only
go build -o bin/nostr-keysign ./tss/cmd/nostr-keysign
```

### Install Globally

```bash
# Install to $GOPATH/bin or $HOME/go/bin
go install ./tss/cmd/nostr-keygen
go install ./tss/cmd/nostr-keysign
```

## nostr-keygen

Generates a shared ECDSA keypair using Multi-Party Computation. All parties must run this command simultaneously with matching session parameters.

### Usage

```bash
nostr-keygen [flags]
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-relays` | Yes | - | Comma-separated list of Nostr relay URLs (e.g., `wss://relay.example.com`) |
| `-npub` | No | - | Local party's Nostr public key (npub...). If not provided, generates a new keypair |
| `-peers` | Yes | - | Comma-separated list of other party npubs (excludes self) |
| `-session` | No | auto-generated | Preshared session ID (must match across all parties) |
| `-session-key` | No | auto-generated | Preshared session encryption key in hex (must match across all parties) |
| `-chaincode` | No | auto-generated | Chain code in hex (must match across all parties) |
| `-timeout` | No | 90 | Maximum timeout in seconds |
| `-nsec-env` | No | NOSTR_NSEC | Environment variable name for nsec (used only if `-npub` is provided) |
| `-ppm` | No | - | Path to pre-params file (optional, for faster keygen) |
| `-output` | No | stdout | Output file for keyshare JSON (default: stdout) |

### Environment Variables

- `NOSTR_NSEC` (or custom name via `-nsec-env`): Required when using `-npub` flag. Contains the Nostr secret key (nsec...) corresponding to the provided npub.

### Examples

#### Example 1: Generate New Keypair (2-Party)

**Party 1:**
```bash
# Generate new keypair (nsec/npub will be printed to stderr)
nostr-keygen \
  -relays "wss://relay1.example.com,wss://relay2.example.com" \
  -peers "npub1party2..." \
  -session "abc123..." \
  -session-key "def456..." \
  -chaincode "789ghi..." \
  -output party1-keyshare.json
```

**Party 2:**
```bash
# Generate new keypair (nsec/npub will be printed to stderr)
nostr-keygen \
  -relays "wss://relay1.example.com,wss://relay2.example.com" \
  -peers "npub1party1..." \
  -session "abc123..." \
  -session-key "def456..." \
  -chaincode "789ghi..." \
  -output party2-keyshare.json
```

#### Example 2: Use Existing Keypair

**Party 1:**
```bash
export NOSTR_NSEC="nsec1..."
nostr-keygen \
  -relays "wss://relay.example.com" \
  -npub "npub1party1..." \
  -peers "npub1party2..." \
  -session "abc123..." \
  -session-key "def456..." \
  -chaincode "789ghi..." \
  -output party1-keyshare.json
```

**Party 2:**
```bash
export NOSTR_NSEC="nsec1..."
nostr-keygen \
  -relays "wss://relay.example.com" \
  -npub "npub1party2..." \
  -peers "npub1party1..." \
  -session "abc123..." \
  -session-key "def456..." \
  -chaincode "789ghi..." \
  -output party2-keyshare.json
```

#### Example 3: Auto-Generate All Parameters

**Party 1:**
```bash
# All parameters auto-generated, but session params must be shared
# First, generate session parameters:
SESSION_ID=$(openssl rand -hex 32)
SESSION_KEY=$(openssl rand -hex 32)
CHAINCODE=$(openssl rand -hex 32)

# Then run (both parties use same SESSION_ID, SESSION_KEY, CHAINCODE)
nostr-keygen \
  -relays "wss://relay.example.com" \
  -peers "npub1party2..." \
  -session "$SESSION_ID" \
  -session-key "$SESSION_KEY" \
  -chaincode "$CHAINCODE" \
  -output party1-keyshare.json
```

### Output

The command outputs a JSON keyshare file containing:
- `pub_key`: The shared public key (same for all parties)
- `chain_code_hex`: The chain code used
- `nostr_npub`: The Nostr public key of this party
- `encrypted_nsec`: The encrypted Nostr secret key (encrypted with the shared key)
- `keygen_committee_keys`: List of all party npubs that participated
- Other TSS-specific fields

### Important Notes

1. **Session Parameters**: `-session`, `-session-key`, and `-chaincode` must be **identical** across all parties
2. **Peer Lists**: Each party's `-peers` flag should list **all other parties** (not including self)
3. **Timing**: All parties must run the command **simultaneously** (within the timeout window)
4. **Relays**: Use reliable, publicly accessible Nostr relays or set up your own
5. **Security**: The generated nsec/npub are printed to stderr - ensure this is not logged in production

## nostr-keysign

Signs a message using a previously generated shared key. All participating parties must run this command simultaneously with matching session parameters.

### Usage

```bash
nostr-keysign [flags]
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `-relays` | Yes | - | Comma-separated list of Nostr relay URLs (e.g., `wss://relay.example.com`) |
| `-nsec` | Yes | - | Local party's Nostr secret key (nsec...) |
| `-peers` | Yes | - | Comma-separated list of **all** party npubs (including self) |
| `-session` | Yes | - | Session ID (must match across all parties) |
| `-session-key` | Yes | - | Session encryption key in hex (must match across all parties) |
| `-keyshare` | Yes | - | Path to keyshare JSON file (from nostr-keygen) |
| `-path` | No | `m/44'/0'/0'/0/0` | HD derivation path |
| `-message` | Yes | - | Message to sign (will be SHA256 hashed) |
| `-timeout` | No | 90 | Maximum timeout in seconds |

### Examples

#### Example 1: Basic 2-Party Signing

**Party 1:**
```bash
nostr-keysign \
  -relays "wss://relay.example.com" \
  -nsec "nsec1party1..." \
  -peers "npub1party1...,npub1party2..." \
  -session "xyz789..." \
  -session-key "abc123..." \
  -keyshare party1-keyshare.json \
  -message "Hello, World!" \
  -path "m/44'/0'/0'/0/0"
```

**Party 2:**
```bash
nostr-keysign \
  -relays "wss://relay.example.com" \
  -nsec "nsec1party2..." \
  -peers "npub1party1...,npub1party2..." \
  -session "xyz789..." \
  -session-key "abc123..." \
  -keyshare party2-keyshare.json \
  -message "Hello, World!" \
  -path "m/44'/0'/0'/0/0"
```

#### Example 2: Sign Transaction Hash

```bash
# Sign a Bitcoin transaction hash
TX_HASH="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

nostr-keysign \
  -relays "wss://relay.example.com" \
  -nsec "$NOSTR_NSEC" \
  -peers "$ALL_PARTIES" \
  -session "$SESSION_ID" \
  -session-key "$SESSION_KEY" \
  -keyshare keyshare.json \
  -message "$TX_HASH"
```

#### Example 3: Custom Derivation Path

```bash
# Use a different derivation path
nostr-keysign \
  -relays "wss://relay.example.com" \
  -nsec "$NOSTR_NSEC" \
  -peers "$ALL_PARTIES" \
  -session "$SESSION_ID" \
  -session-key "$SESSION_KEY" \
  -keyshare keyshare.json \
  -message "Sign this" \
  -path "m/84'/0'/0'/0/1"  # Native SegWit, account 0, change address 1
```

### Output

The command outputs a JSON signature to stdout:
```json
{
  "r": "signature_r_component",
  "s": "signature_s_component"
}
```

**Important**: All parties will produce the **same signature** - this is expected and correct for MPC signing.

### Important Notes

1. **Peer List**: The `-peers` flag must include **all participating parties** (including self), unlike keygen where it excludes self
2. **Session Parameters**: `-session` and `-session-key` must be **identical** across all parties
3. **Message**: The message is SHA256 hashed internally - provide the raw message, not the hash
4. **Keyshare**: Each party must use their **own keyshare file** from the keygen phase
5. **Timing**: All parties must run the command **simultaneously** (within the timeout window)
6. **Subset Signing**: You can use a subset of parties for signing (e.g., 2 out of 3), but all participating parties must be listed in `-peers`

## Complete Workflow Example

### Step 1: Generate Session Parameters

```bash
# Generate once and share securely with all parties
SESSION_ID=$(openssl rand -hex 32)
SESSION_KEY=$(openssl rand -hex 32)
CHAINCODE=$(openssl rand -hex 32)

echo "SESSION_ID=$SESSION_ID"
echo "SESSION_KEY=$SESSION_KEY"
echo "CHAINCODE=$CHAINCODE"
```

### Step 2: Run Keygen (All Parties Simultaneously)

**Party 1:**
```bash
export NOSTR_NSEC="nsec1party1..."
export RELAYS="wss://relay1.example.com,wss://relay2.example.com"

nostr-keygen \
  -relays "$RELAYS" \
  -npub "npub1party1..." \
  -peers "npub1party2..." \
  -session "$SESSION_ID" \
  -session-key "$SESSION_KEY" \
  -chaincode "$CHAINCODE" \
  -output party1-keyshare.json
```

**Party 2:**
```bash
export NOSTR_NSEC="nsec1party2..."
export RELAYS="wss://relay1.example.com,wss://relay2.example.com"

nostr-keygen \
  -relays "$RELAYS" \
  -npub "npub1party2..." \
  -peers "npub1party1..." \
  -session "$SESSION_ID" \
  -session-key "$SESSION_KEY" \
  -chaincode "$CHAINCODE" \
  -output party2-keyshare.json
```

### Step 3: Verify Keyshares Match

```bash
# Extract and compare public keys (should be identical)
jq -r '.pub_key' party1-keyshare.json
jq -r '.pub_key' party2-keyshare.json
```

### Step 4: Generate Keysign Session Parameters

```bash
# Generate new session parameters for signing
KEYSIGN_SESSION_ID=$(openssl rand -hex 32)
KEYSIGN_SESSION_KEY=$(openssl rand -hex 32)
```

### Step 5: Run Keysign (All Parties Simultaneously)

**Party 1:**
```bash
export NOSTR_NSEC="nsec1party1..."
export RELAYS="wss://relay1.example.com,wss://relay2.example.com"
export ALL_PARTIES="npub1party1...,npub1party2..."

nostr-keysign \
  -relays "$RELAYS" \
  -nsec "$NOSTR_NSEC" \
  -peers "$ALL_PARTIES" \
  -session "$KEYSIGN_SESSION_ID" \
  -session-key "$KEYSIGN_SESSION_KEY" \
  -keyshare party1-keyshare.json \
  -message "Transaction to sign" \
  > party1-signature.json
```

**Party 2:**
```bash
export NOSTR_NSEC="nsec1party2..."
export RELAYS="wss://relay1.example.com,wss://relay2.example.com"
export ALL_PARTIES="npub1party1...,npub1party2..."

nostr-keysign \
  -relays "$RELAYS" \
  -nsec "$NOSTR_NSEC" \
  -peers "$ALL_PARTIES" \
  -session "$KEYSIGN_SESSION_ID" \
  -session-key "$KEYSIGN_SESSION_KEY" \
  -keyshare party2-keyshare.json \
  -message "Transaction to sign" \
  > party2-signature.json
```

### Step 6: Verify Signatures Match

```bash
# Signatures should be identical
diff party1-signature.json party2-signature.json
# Should produce no output (files are identical)
```

## Troubleshooting

### Common Issues

#### 1. "Error: -relays and -peers are required"
- **Solution**: Ensure all required flags are provided. Use `-h` flag to see usage.

#### 2. "Error: nsec not found in environment variable"
- **Solution**: Set the `NOSTR_NSEC` environment variable (or custom name via `-nsec-env`) when using `-npub` flag.

#### 3. "Error: await peers: timeout"
- **Solution**: 
  - Ensure all parties are running simultaneously
  - Check relay connectivity
  - Verify session parameters match exactly
  - Increase timeout with `-timeout` flag

#### 4. "Error: keygen failed" or "Error: keysign failed"
- **Solution**:
  - Check relay connectivity
  - Verify all parties are online and running
  - Ensure session parameters match exactly
  - Check logs for detailed error messages

#### 5. "Warning: keyshare npub does not match derived npub"
- **Solution**: The nsec provided doesn't match the npub in the keyshare. Use the correct nsec for the keyshare.

#### 6. Public keys don't match after keygen
- **Solution**: This should never happen if keygen completed successfully. If it does, there was an error - re-run keygen.

#### 7. Signatures don't match after keysign
- **Solution**: This should never happen if keysign completed successfully. If it does, there was an error - re-run keysign.

### Debugging Tips

1. **Check Relay Connectivity**: Test relay URLs with a Nostr client
2. **Verify Session Parameters**: Use `echo` to verify all parties have identical session parameters
3. **Check Timing**: Ensure all parties start within a few seconds of each other
4. **Increase Timeout**: Use `-timeout 300` or higher for slower networks
5. **Use Multiple Relays**: Provide multiple relay URLs for redundancy: `-relays "wss://relay1.com,wss://relay2.com"`

### Getting Help

```bash
# Show usage for nostr-keygen
nostr-keygen -h

# Show usage for nostr-keysign
nostr-keysign -h
```

## Security Considerations

1. **Session Parameters**: Generate session parameters using cryptographically secure random number generators
2. **Nsec Storage**: Never log or expose nsec values - they provide full control over Nostr identity
3. **Relay Selection**: Use trusted relays or set up your own for production use
4. **Network Security**: Consider using relays over TLS (wss://) in production
5. **Key Management**: Securely store keyshare files - they contain encrypted secrets
6. **Timing Attacks**: Be aware that timing of operations may leak information

## Testing

See [test-cmd.sh](./test-cmd.sh) for automated testing of both commands.

```bash
# Run tests
./test-cmd.sh
```

## Related Documentation

- [COMPARISON.md](./COMPARISON.md) - Comparison with mpc_nostr.go implementation
- [../../README.md](../../README.md) - Main library documentation
- [../../scripts/](../../scripts/) - Example scripts using these commands
