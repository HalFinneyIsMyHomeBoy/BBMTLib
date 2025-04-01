package tss

import (
	"time"

	"context"
	"encoding/json"
	"log"

	"github.com/patrickmn/go-cache"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// Global Cache
var messageCache = cache.New(5*time.Minute, 10*time.Minute)

type ProtoMessage struct {
	Type         string   `json:"type"`
	Participants []string `json:"participants"`
	Recipients   []string `json:"recipients"`
	SessionID    string   `json:"sessionID"`
	Datetime     string   `json:"datetime"`
	SeqNo        string   `json:"sequence_no"`
	RawMessage   string   `json:"raw_message"`
}

type RawMessage struct {
	SessionID string   `json:"session_id,omitempty"`
	From      string   `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	Body      string   `json:"body,omitempty"`
	SeqNo     string   `json:"sequence_no,omitempty"`
	Hash      string   `json:"hash,omitempty"`
}

type NostrStatus struct {
	SessionID string `json:"session_id,omitempty"`
	Status    string `json:"status,omitempty"`
}

type NostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"` //sender pubkey
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`    //recipients
	Content   string     `json:"content"` //raw message
	Sig       string     `json:"sig"`
}

func setNPubs() {
	// set the nostr pubkeys for the participants

}

func hanshake() {

}

// NOSTR Callback
func nostrListen(nostrRelay string, nostrPubKey string, nostrPrivKey string) {

	// senderPrivkey string, recipients []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relay, err := nostr.RelayConnect(ctx, nostrRelay)
	if err != nil {
		log.Printf("Error connecting to relay: %v\n", err)
		return
	}
	defer relay.Close()

	cutoffTime := time.Now().Add(-5 * time.Minute)
	since := nostr.Timestamp(cutoffTime.Unix())

	filters := nostr.Filters{
		{
			Kinds: []int{nostr.KindEncryptedDirectMessage},
			Tags:  nostr.TagMap{"p": []string{nostrPubKey}}, //Only messages for this pubkey
			Since: &since,
		},
	}

	sub, err := relay.Subscribe(ctx, filters)
	if err != nil {
		log.Printf("Error subscribing to events: %v\n", err)
		return
	}

	for {
		select {
		case event := <-sub.Events:
			sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, nostrPrivKey) //TODO: event.PubKey should be senderPubkey???
			if err != nil {
				log.Printf("Error computing shared secret: %v\n", err)
				continue
			}

			decryptedMessage, err := nip04.Decrypt(event.Content, sharedSecret)
			if err != nil {
				log.Printf("Error decrypting message: %v\n", err)
				continue
			}

			// Parse the decrypted message into a RawMessage
			var rawMessage RawMessage
			if err := json.Unmarshal([]byte(decryptedMessage), &rawMessage); err != nil {
				log.Printf("Error parsing decrypted message into RawMessage: %v\n", err)
				continue
			}

			log.Printf("Parsed RawMessage: %+v\n", rawMessage)

			// Store the parsed raw message in cache using the session ID
			messageCache.Set(rawMessage.SessionID, rawMessage, cache.DefaultExpiration)

		case <-ctx.Done():
			return

		case <-sub.EndOfStoredEvents:
			//fmt.Printf("Received all stored events, continuing to listen...\n")
		}
	}

	// whenever we receive a message just push it to the cache
	//sessionID := NostrStatus.SessionID
	//messageRaw := "some_json_tss_message"
	//messageCache.Set(sessionID, rawMessage{nil})
}

func nostSend(session, raw_message string) {
	// nostr implementation to send the proto_message
}

func nostrDownloadMessage(sessionID string) (string, error) {
	messageCache.Get(sessionID)
}
