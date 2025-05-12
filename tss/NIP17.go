package tss

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
)

const (
	// Two days in seconds for randomizing created_at
	TWO_DAYS = 2 * 24 * 60 * 60
)

// Rumor represents a kind:14 rumor (unsigned chat message)
type Rumor struct {
	nostr.Event
	ID string
}

// Helper function to get current UNIX timestamp
func now() nostr.Timestamp {
	return nostr.Timestamp(time.Now().Unix())
}

// Helper function to get randomized timestamp (within past 2 days)
func randomNow() nostr.Timestamp {
	return now() - nostr.Timestamp(rand.Float64()*TWO_DAYS)
}

// CreateRumor creates a kind:14 rumor (unsigned chat message)
func createRumor(content string, senderPubkey string, recipientPubkey string) Rumor {
	rumor := Rumor{
		Event: nostr.Event{
			Kind:      14, // NIP-17 kind for chat messages
			CreatedAt: now(),
			PubKey:    senderPubkey,
			Content:   content,
			Tags:      nostr.Tags{{"p", recipientPubkey}},
		},
	}
	// Calculate event ID
	rumor.ID = rumor.Event.GetID()
	return rumor
}

// CreateSeal encrypts the rumor into a kind:13 seal
func createSeal(rumor Rumor, senderPrivkey string, recipientPubkey string) (*nostr.Event, error) {
	// Serialize rumor to JSON
	rumorJSON, err := json.Marshal(rumor)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize rumor: %w", err)
	}

	// Generate conversation key
	conversationKey, err := nip44.GenerateConversationKey(recipientPubkey, senderPrivkey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate conversation key: %w", err)
	}

	// Encrypt rumor using NIP-44
	encryptedContent, err := nip44.Encrypt(string(rumorJSON), conversationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt rumor: %w", err)
	}

	// Create seal event (kind:13)
	seal := &nostr.Event{
		Kind:      13,
		CreatedAt: randomNow(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{},
	}
	// Sign the seal
	if err := seal.Sign(senderPrivkey); err != nil {
		return nil, fmt.Errorf("failed to sign seal: %w", err)
	}
	return seal, nil
}

// CreateWrap creates a kind:1059 gift wrap for the seal
func createWrap(seal *nostr.Event, recipientPubkey string) (*nostr.Event, error) {
	// Generate a random private key for the gift wrap
	randomKey := nostr.GeneratePrivateKey()
	randomPubkey, err := nostr.GetPublicKey(randomKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random pubkey: %w", err)
	}

	// Serialize seal to JSON
	sealJSON, err := json.Marshal(seal)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize seal: %w", err)
	}

	// Generate conversation key
	conversationKey, err := nip44.GenerateConversationKey(recipientPubkey, randomKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate conversation key: %w", err)
	}

	// Encrypt seal using NIP-44
	encryptedContent, err := nip44.Encrypt(string(sealJSON), conversationKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt seal: %w", err)
	}

	// Create gift wrap event (kind:1059)
	wrap := &nostr.Event{
		Kind:      1059,
		PubKey:    randomPubkey,
		CreatedAt: randomNow(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{{"p", recipientPubkey}},
	}
	// Sign the gift wrap
	if err := wrap.Sign(randomKey); err != nil {
		return nil, fmt.Errorf("failed to sign wrap: %w", err)
	}
	return wrap, nil
}

// SendMessage sends an encrypted NIP-17 message
func SendMessage(senderNsec, recipientNpub, message, relayURL string) error {
	// Decode sender's private key and recipient's public key
	_, senderPrivkey, err := nip19.Decode(senderNsec)
	if err != nil {
		return fmt.Errorf("invalid sender nsec: %w", err)
	}
	senderPubkey, err := nostr.GetPublicKey(senderPrivkey.(string))
	if err != nil {
		return fmt.Errorf("failed to derive sender pubkey: %w", err)
	}
	_, recipientPubkey, err := nip19.Decode(recipientNpub)
	if err != nil {
		return fmt.Errorf("invalid recipient npub: %w", err)
	}

	// Create rumor
	rumor := createRumor(message, senderPubkey, recipientPubkey.(string))

	// Create seal for recipient
	seal, err := createSeal(rumor, senderPrivkey.(string), recipientPubkey.(string))
	if err != nil {
		return fmt.Errorf("failed to create seal: %w", err)
	}

	// Create gift wrap for recipient
	wrap, err := createWrap(seal, recipientPubkey.(string))
	if err != nil {
		return fmt.Errorf("failed to create wrap: %w", err)
	}

	// Connect to relay
	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()

	// Publish gift wrap
	if err := relay.Publish(ctx, *wrap); err != nil {
		return fmt.Errorf("failed to publish gift wrap: %w", err)
	}
	fmt.Printf("Published gift wrap to %s\n", relayURL)
	return nil
}

// ReceiveMessage listens for and decrypts NIP-17 messages
func ReceiveMessage(recipientNsec, relayURL string) error {
	// Decode recipient's private key
	_, recipientPrivkey, err := nip19.Decode(recipientNsec)
	if err != nil {
		return fmt.Errorf("invalid recipient nsec: %w", err)
	}
	recipientPubkey, err := nostr.GetPublicKey(recipientPrivkey.(string))
	if err != nil {
		return fmt.Errorf("failed to derive recipient pubkey: %w", err)
	}

	// Connect to relay
	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return fmt.Errorf("failed to connect to relay %s: %w", relayURL, err)
	}
	defer relay.Close()

	// Subscribe to kind:1059 events addressed to the recipient
	filters := []nostr.Filter{{
		Kinds: []int{1059},
		Tags:  map[string][]string{"p": {recipientPubkey}},
	}}
	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Listen for events
	for ev := range sub.Events {
		// Generate conversation key for gift wrap
		conversationKey, err := nip44.GenerateConversationKey(ev.PubKey, recipientPrivkey.(string))
		if err != nil {
			fmt.Printf("Failed to generate conversation key: %v\n", err)
			continue
		}

		// Decrypt gift wrap content (kind:1059)
		sealJSON, err := nip44.Decrypt(ev.Content, conversationKey)
		if err != nil {
			fmt.Printf("Failed to decrypt gift wrap: %v\n", err)
			continue
		}

		// Deserialize seal
		var seal nostr.Event
		if err := json.Unmarshal([]byte(sealJSON), &seal); err != nil {
			fmt.Printf("Failed to deserialize seal: %v\n", err)
			continue
		}

		// Generate conversation key for seal
		sealConversationKey, err := nip44.GenerateConversationKey(seal.PubKey, recipientPrivkey.(string))
		if err != nil {
			fmt.Printf("Failed to generate seal conversation key: %v\n", err)
			continue
		}

		// Decrypt seal content (kind:13)
		rumorJSON, err := nip44.Decrypt(seal.Content, sealConversationKey)
		if err != nil {
			fmt.Printf("Failed to decrypt seal: %v\n", err)
			continue
		}

		// Deserialize rumor
		var rumor Rumor
		if err := json.Unmarshal([]byte(rumorJSON), &rumor); err != nil {
			fmt.Printf("Failed to deserialize rumor: %v\n", err)
			continue
		}

		// Verify pubkey matches (prevent impersonation)
		if rumor.PubKey != seal.PubKey {
			fmt.Println("Warning: Pubkey mismatch, possible impersonation")
			continue
		}

		fmt.Printf("Received message from %s: %s\n", rumor.PubKey, rumor.Content)
	}
	return nil
}

func main() {
	// Example keys (replace with real keys)
	senderNsec := "nsec1..."    // Sender's private key
	recipientNpub := "npub1..." // Recipient's public key
	relayURL := "wss://relay.damus.io"
	message := "Hola, que tal?"

	// Seed random for created_at randomization
	rand.Seed(time.Now().UnixNano())

	// Send a message
	fmt.Println("Sending message...")
	if err := SendMessage(senderNsec, recipientNpub, message, relayURL); err != nil {
		fmt.Printf("Failed to send message: %v\n", err)
	}

	// Receive messages (run in a separate process or goroutine in practice)
	fmt.Println("Listening for messages...")
	if err := ReceiveMessage(senderNsec, relayURL); err != nil {
		fmt.Printf("Failed to receive messages: %v\n", err)
	}
}
