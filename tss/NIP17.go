package tss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/nbd-wtf/go-nostr"
)

// NIP-17 encryption/decryption implementation
// Based on draft specification: https://github.com/nostr-protocol/nips/pull/17

// Encrypt encrypts a message using NIP-17
func NIP17Encrypt(message string, recipientPubKey string, senderPrivKey string) (string, error) {
	// Generate ephemeral key pair
	ephemeralPrivKey := nostr.GeneratePrivateKey()
	ephemeralPubKey, err := nostr.GetPublicKey(ephemeralPrivKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate ephemeral public key: %w", err)
	}

	// Compute shared secret using ephemeral private key and recipient's public key
	sharedSecret, err := computeSharedSecret(ephemeralPrivKey, recipientPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Generate random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt message
	ciphertext := gcm.Seal(nil, nonce, []byte(message), nil)

	// Combine nonce and ciphertext
	combined := append(nonce, ciphertext...)

	// Create NIP-17 message format
	nip17Msg := map[string]string{
		"ephemeral_pubkey": ephemeralPubKey,
		"ciphertext":       base64.StdEncoding.EncodeToString(combined),
	}

	// Convert to JSON
	nip17JSON, err := json.Marshal(nip17Msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal NIP-17 message: %w", err)
	}

	return string(nip17JSON), nil
}

// Decrypt decrypts a NIP-17 encrypted message
func NIP17Decrypt(encryptedMessage string, recipientPrivKey string) (string, error) {
	// Parse NIP-17 message
	var nip17Msg map[string]string
	if err := json.Unmarshal([]byte(encryptedMessage), &nip17Msg); err != nil {
		return "", fmt.Errorf("failed to parse NIP-17 message: %w", err)
	}

	// Get ephemeral public key and ciphertext
	ephemeralPubKey, ok := nip17Msg["ephemeral_pubkey"]
	if !ok {
		return "", fmt.Errorf("missing ephemeral public key")
	}

	ciphertext, ok := nip17Msg["ciphertext"]
	if !ok {
		return "", fmt.Errorf("missing ciphertext")
	}

	// Compute shared secret using recipient's private key and ephemeral public key
	sharedSecret, err := computeSharedSecret(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Decode ciphertext
	combined, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	// Extract nonce and ciphertext
	if len(combined) < 12 {
		return "", fmt.Errorf("invalid ciphertext length")
	}
	nonce := combined[:12]
	ciphertextBytes := combined[12:]

	// Create AES cipher
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt message
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(plaintext), nil
}

// computeSharedSecret computes the shared secret using ECDH
func computeSharedSecret(privateKey string, publicKey string) ([]byte, error) {
	// Convert private key to bytes
	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	// Convert public key to bytes
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Create private key
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	// For Nostr public keys (32 bytes), we need to convert to Bitcoin format (33 bytes)
	// Add 0x02 prefix for compressed public key
	compressedPubKey := make([]byte, 33)
	compressedPubKey[0] = 0x02 // compressed format
	copy(compressedPubKey[1:], pubKeyBytes)

	// Parse public key
	pubKey, err := btcec.ParsePubKey(compressedPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedSecret := btcec.GenerateSharedSecret(privKey, pubKey)

	// Hash the shared secret using SHA-256
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}
