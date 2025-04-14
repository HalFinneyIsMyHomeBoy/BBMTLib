package tss

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
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
	nostrRelay        string = "ws://bbw-nostr.xyz"
)

type ProtoMessage struct {
	Type         string   `json:"type"`
	Participants []string `json:"participants"`
	Recipients   []string `json:"recipients"`
	SessionID    string   `json:"sessionID"`
	Datetime     string   `json:"datetime"`
	SeqNo        string   `json:"sequence_no"`
	RawMessage   string   `json:"raw_message"`
	RequestPath  string   `json:"request_path"`
	RequestType  string   `json:"request_type"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	NostrEventID string   `json:"nostr_event_id"`
	SessionKey   string   `json:"session_key"`
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

func GetMaster(currentParties string, localParty string) (string, string) {
	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return "", ""
	}

	var masterPeer string
	var masterPubKey string
	parties := strings.Split(currentParties, ",")
	for _, peer := range parties {
		if pubKey, ok := keyShare.NostrPartyPubKeys[peer]; ok {
			if pubKey > masterPubKey {
				masterPubKey = pubKey
				masterPeer = peer
			}
		}
	}
	return masterPeer, masterPubKey
}

func isMaster(currentParties string, localParty string) bool {
	masterPeer, _ := GetMaster(currentParties, localParty)
	if masterPeer == localParty {
		return true
	}
	return false
}

// func GetMaster(currentParties string) (string, string) {

// 	parties := strings.Split(currentParties, ",")
// 	for _, peer := range parties {
// 		keyShare, err := GetKeyShare(peer)
// 		if err != nil {
// 			log.Printf("Error getting key share: %v\n", err)
// 			continue
// 		}
// 		if keyShare.LocalNostrPubKey > masterPubKey {
// 			masterPeer := peer
// 			masterPubKey := keyShare.LocalNostrPubKey
// 		}
// 	}
// 	return masterPeer, masterPubKey
// }

// func isMaster(party string) bool {
// 	keyShare, err := GetKeyShare(party)
// 	if err != nil {
// 		log.Printf("Error getting key share: %v\n", err)
// 		return false
// 	}
// 	masterPeer, _ := GetMaster(keyShare)
// 	if masterPeer == party {
// 		return true
// 	}
// 	return false
// }

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
func nostrListen(localParty, parties string) {

	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}
	masterPeer, masterPubKey := GetMaster(parties, localParty)

	var isMaster bool
	var port string = "55055"

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

	// // Convert hex private key to nsec format
	// npubFromPriv, err := nostr.GetPublicKey(keyShare.LocalNostrPrivKey)
	// if err != nil {
	// 	log.Printf("Error getting public key from private key: %v\n", err)
	// 	return
	// }
	// if !nostr.IsValidPublicKey(npubFromPriv) {
	// 	log.Printf("Invalid public key derived from private key\n")
	// 	return
	// }
	// keyShare.LocalNostrPubKey = npubFromPriv

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
			var protoMessage ProtoMessage
			if err := json.Unmarshal([]byte(decryptedMessage), &protoMessage); err != nil {
				log.Printf("Error parsing decrypted message into RawMessage: %v\n", err)
				continue
			}
			protoMessage.NostrEventID = event.ID
			//log.Printf("Parsed RawMessage: %+v\n", rawMessage)

			// Store the parsed raw message in cache using the session ID
			nostrMessageCache.Set(protoMessage.SessionID, protoMessage, cache.DefaultExpiration)

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

func nostrSend(sessionID, key, message, requestPath, requestType, fromParty, toParty, parties string) {

	// Initialize context if nil
	if globalCtx == nil {
		globalCtx = context.Background()
	}

	keyShare, err := GetKeyShare(fromParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	var recipientPubKey string
	for peer, pubKey := range keyShare.NostrPartyPubKeys {
		if peer == toParty {
			recipientPubKey = pubKey
			break
		}
	}

	var rawMsg RawMessage
	if err := json.Unmarshal([]byte(message), &rawMsg); err != nil {
		log.Printf("Failed to parse RawMessage: %v\n", err)
		return
	}

	protoMessage := ProtoMessage{
		SessionID:    sessionID,
		RequestPath:  requestPath,
		RequestType:  requestType,
		From:         fromParty,
		Participants: []string{parties},
		Recipients:   []string{recipientPubKey},
		Datetime:     time.Now().Format(time.RFC3339),
		RawMessage:   message,
		SeqNo:        rawMsg.SeqNo,
		To:           toParty,
	}

	time.Sleep(3 * time.Second)
	protoMessageJSON, err := json.Marshal(protoMessage)
	if err != nil {
		log.Printf("Error marshalling protoMessage: %v\n", err)
		return
	}

	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubKey, keyShare.LocalNostrPrivKey)
	if err != nil {
		log.Printf("Error computing shared secret: %v\n", err)
		return
	}

	encryptedContent, err := nip04.Encrypt(string(protoMessageJSON), sharedSecret)
	if err != nil {
		log.Printf("Error encrypting message: %v\n", err)
		return
	}

	event := nostr.Event{
		PubKey:    keyShare.LocalNostrPubKey,
		CreatedAt: nostr.Now(),
		Kind:      nostr.KindEncryptedDirectMessage,
		Tags:      nostr.Tags{{"p", recipientPubKey}, {"s", rawMsg.SeqNo}},
		Content:   encryptedContent,
	}

	event.Sign(keyShare.LocalNostrPrivKey)

	ctx, cancel := context.WithTimeout(globalCtx, 60*time.Second)
	defer cancel()

	err = globalRelay.Publish(ctx, event)
	//time.Sleep(2 * time.Second)
	if err != nil {
		log.Printf("Error publishing event: %v\n", err)
		return
	}

}

func nostrDownloadMessage(sessionID string, key string) (ProtoMessage, error) {
	msg, found := nostrMessageCache.Get(sessionID)
	if !found {
		return ProtoMessage{}, fmt.Errorf("message not found for session %s", sessionID)
	}
	// protoMsg := msg.(ProtoMessage)
	// if protoMsg.To == key {
	// 	return protoMsg, nil
	// }
	return msg.(ProtoMessage), nil
	// protoMsg := msg.(ProtoMessage)
	// var rawMsg RawMessage
	// if err := json.Unmarshal([]byte(protoMsg.RawMessage), &rawMsg); err != nil {
	// 	return ProtoMessage{}, fmt.Errorf("failed to parse raw message: %w", err)
	// }
	// if rawMsg.To[0] == key {
	// 	// Unmarshal the protoMsg into a ProtoMessage struct
	// 	var protoMessage ProtoMessage
	// 	if err := json.Unmarshal([]byte(protoMsg.RawMessage), &protoMessage); err != nil {
	// 		return ProtoMessage{}, fmt.Errorf("failed to unmarshal proto message: %w", err)
	// 	}
	// 	return protoMessage, nil
	// }
	// return ProtoMessage{}, fmt.Errorf("message not found for session %s", sessionID)
}
