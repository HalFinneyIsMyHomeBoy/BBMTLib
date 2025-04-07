package tss

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/patrickmn/go-cache"
)

// Global variables
var (
	nostrMessageCache = cache.New(5*time.Minute, 10*time.Minute)
	globalRelay       *nostr.Relay
	globalCtx         context.Context
)

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

func GetKeyShare(party string) (LocalState, error) {

	data, err := os.ReadFile(party + ".ks")
	if err != nil {
		fmt.Printf("Go Error GetKeyShare: %v\n", err)
	}

	// Decode base64
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		fmt.Printf("Go Error Decoding Base64: %v\n", err)
	}

	// Parse JSON into LocalState
	var keyShare LocalState
	if err := json.Unmarshal(decodedData, &keyShare); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v\n", err)
	}

	return keyShare, nil
}

func GetMaster(keyShare LocalState) (string, string) {
	var masterPeer string
	var masterPubKey string
	for peer, key := range keyShare.NostrPartyPubKeys {
		if key > masterPubKey { // Direct string comparison
			masterPubKey = key
			masterPeer = peer
		}
	}
	return masterPeer, masterPubKey
}

func setNPubs() {
	// set the nostr pubkeys for the participants

}

func nostrHandshake() {
	// handshake with the master

}

func validateKeys(privateKey, publicKey string) error {
	if len(privateKey) != 64 || !nostr.IsValidPublicKey(publicKey) {
		return fmt.Errorf("invalid key format")
	}
	derivedPubKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Errorf("error deriving public key: %v", err)
	}
	if derivedPubKey != publicKey {
		return fmt.Errorf("private key does not match public key")
	}
	return nil
}

// NOSTR Callback
func nostrListen(localParty string) {

	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}
	masterPeer, masterPubKey := GetMaster(keyShare)

	var isMaster bool
	var port string = "55055"
	var nostrRelay string = "ws://bbw-nostr.xyz"

	if masterPeer == keyShare.LocalPartyKey && masterPubKey == keyShare.LocalNostrPubKey {
		// we are the master, so we start the host
		isMaster = true
		fmt.Printf("%s is master\n", localParty)
	} else {
		isMaster = false
	}

	if isMaster {
		RunRelay(port)
		fmt.Printf("relay started by %s\n", localParty)
		//select {}
	}

	// Convert hex private key to nsec format
	npubFromPriv, err := nostr.GetPublicKey(keyShare.LocalNostrPrivKey)
	if err != nil {
		log.Printf("Error getting public key from private key: %v\n", err)
		return
	}
	if !nostr.IsValidPublicKey(npubFromPriv) {
		log.Printf("Invalid public key derived from private key\n")
		return
	}
	keyShare.LocalNostrPubKey = npubFromPriv

	// Validate the public key format
	if !nostr.IsValidPublicKey(keyShare.LocalNostrPubKey) {
		log.Printf("Invalid public key format\n")
		return
	}

	if err := validateKeys(keyShare.LocalNostrPrivKey, keyShare.LocalNostrPubKey); err != nil {
		log.Printf("Key validation error: %v\n", err)
		return
	}

	//log.Printf("Local Nostr PubKey: %s\n", keyShare.LocalNostrPubKey)
	//log.Printf("Local Nostr PrivKey: %s\n", keyShare.LocalNostrPrivKey)

	//fmt.Printf("%s Listening for messages on nostr\n", localParty)
	// senderPrivkey string, recipients []string
	globalCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var relayErr error
	globalRelay, relayErr = nostr.RelayConnect(globalCtx, nostrRelay)
	if relayErr != nil {
		log.Printf("Error connecting to relay: %v\n", relayErr)
		return
	}
	defer globalRelay.Close()

	cutoffTime := time.Now().Add(-5 * time.Minute)
	since := nostr.Timestamp(cutoffTime.Unix())

	filters := nostr.Filters{
		{
			Kinds: []int{nostr.KindEncryptedDirectMessage},
			Tags:  nostr.TagMap{"p": []string{keyShare.LocalNostrPubKey}},
			Since: &since,
		},
	}

	sub, err := globalRelay.Subscribe(globalCtx, filters)
	if err != nil {
		log.Printf("Error subscribing to events: %v\n", err)
		return
	}
	fmt.Printf("%s subscribed to nostr\n", localParty)
	for {
		select {
		case event := <-sub.Events:
			sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, keyShare.LocalNostrPrivKey) //TODO: event.PubKey should be senderPubkey???
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
			nostrMessageCache.Set(rawMessage.SessionID, rawMessage, cache.DefaultExpiration)

		case <-globalCtx.Done():
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

func nostrSend(sessionID, message string) {
	// Initialize context if nil
	if globalCtx == nil {
		globalCtx = context.Background()
	}

	var rawMessage RawMessage
	// if msg, found := nostrMessageCache.Get(sessionID); found {
	// 	rawMessage = msg.(RawMessage)
	// 	log.Printf("RawMessage: %v\n", rawMessage)
	// } else {
	// 	log.Printf("Message not found in cache for session ID: %s\n", sessionID)
	// 	return
	// }

	//messageBytes, err := json.Marshal(message)
	if err := json.Unmarshal([]byte(message), &rawMessage); err != nil {
		log.Printf("Error parsing message into RawMessage: %v\n", err)
		return
	}

	keyShare, err := GetKeyShare(rawMessage.From)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	// Construct ProtoMessage
	// protoMessage := ProtoMessage{
	// 	Type:         "keysign",
	// 	Participants: []string{rawMessage.From},
	// 	Recipients:   rawMessage.To,
	// 	SessionID:    rawMessage.SessionID,
	// 	Datetime:     time.Now().UTC().Format(time.RFC3339),
	// 	SeqNo:        rawMessage.SeqNo,
	// 	RawMessage:   rawMessage.Body,
	// }

	// Marshal the ProtoMessage to JSON
	// message, err := json.Marshal(protoMessage)
	// if err != nil {
	// 	log.Printf("Error marshaling ProtoMessage: %v\n", err)
	// 	return
	// }

	// masterPeer, masterPubKey := GetMaster(keyShare)

	// if masterPeer == keyShare.LocalPartyKey && masterPubKey == keyShare.LocalNostrPubKey {
	// 	// we are the master
	// 	isMaster = true
	// 	//fmt.Printf("%s is master\n", rawMessage.From)
	// } else {
	// 	isMaster = false
	// }

	// Find which peer number corresponds to the recipient pubkey
	var recipientPubKey string
	for peer, pubKey := range keyShare.NostrPartyPubKeys {
		if peer == rawMessage.To[0] {
			recipientPubKey = pubKey
			break
		}
	}

	privateKey := keyShare.LocalNostrPrivKey
	// recipientPubKey, err = nostr.GetPublicKey(recipientPubKey)
	// if err != nil {
	// 	log.Printf("Error getting public key: %v\n", err)
	// 	return
	// }
	// if err := validateKeys(privateKey, recipientPubKey); err != nil {
	// 	log.Printf("Key validation error: %v\n", err)
	// 	return
	// }

	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubKey, privateKey)
	if err != nil {
		log.Printf("Error computing shared secret: %v\n", err)
		return
	}

	finalMessage := string(message)

	encryptedContent, err := nip04.Encrypt(finalMessage, sharedSecret)
	if err != nil {
		log.Printf("Error encrypting message: %v\n", err)
		return
	}

	event := nostr.Event{
		PubKey:    keyShare.LocalNostrPubKey,
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{{"p", recipientPubKey}},
		Content:   encryptedContent,
	}

	event.Sign(privateKey)

	ctx, cancel := context.WithTimeout(globalCtx, 5*time.Second)
	defer cancel()

	err = globalRelay.Publish(ctx, event)
	//time.Sleep(1 * time.Second)
	if err != nil {
		log.Printf("Error publishing event: %v\n", err)
		return
	}
}

func nostrCacheSet(sessionID string, message string) {
	// Create a RawMessage struct with the provided data
	// rawMessage := RawMessage{
	// 	SessionID: sessionID,
	// 	Body:      message,
	// }
	//TODO: this is where the problem is.  Making sure the structs are correct
	// Store the RawMessage in cache
	nostrMessageCache.Set(sessionID, message, cache.DefaultExpiration)

	// Send the message
	nostrSend(sessionID, message)
}

func nostrDownloadMessage(sessionID string, key string) (string, error) {
	if msg, found := nostrMessageCache.Get(sessionID); found {
		switch v := msg.(type) {
		case string:
			return v, nil
		case RawMessage:
			return v.Body, nil
		default:
			return "", fmt.Errorf("unexpected message type: %T", msg)
		}
	}
	return "", fmt.Errorf("message not found for session %s", sessionID)
}
