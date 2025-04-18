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
	//nostrHandShakeCache = cache.New(5*time.Minute, 10*time.Minute)
	nostrHandShakeList []ProtoMessage
	nostrMessageCache  = cache.New(5*time.Minute, 10*time.Minute)
	globalRelay        *nostr.Relay
	globalCtx          context.Context
	nostrRelay         string = "ws://bbw-nostr.xyz"
)

type NostrPartyPubKeys struct {
	Peer   string `json:"peer"`
	PubKey string `json:"pubkey"`
}

type ProtoMessage struct {
	Type            string              `json:"type"`
	Participants    []string            `json:"participants"`
	Recipients      []NostrPartyPubKeys `json:"recipients"`
	FromNostrPubKey string              `json:"from_nostr_pubkey"`
	SessionID       string              `json:"sessionID"`
	Datetime        string              `json:"datetime"`
	SeqNo           string              `json:"sequence_no"`
	RawMessage      string              `json:"raw_message"`
	From            string              `json:"from"`
	To              string              `json:"to"`
	SessionKey      string              `json:"session_key"`
	TxRequest       TxRequest           `json:"tx_request"`
	Master          Master              `json:"master"`
}

type Master struct {
	MasterPeer   string `json:"master_peer"`
	MasterPubKey string `json:"master_pubkey"`
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

type TxRequest struct {
	SenderAddress   string `json:"sender_address"`
	ReceiverAddress string `json:"receiver_address"`
	AmountSatoshi   int64  `json:"amount_satoshi"`
	FeeSatoshi      int64  `json:"fee_satoshi"`
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

//=======================================================
// By default, all parties enable nostr listen

// a random peer wants a keysign
// - sends handshake + session + peer name
// - other peers see handshake and send back session, peer name + (ack handshake?)
// -

// timeout of 10 seconds to hear back from parties?
// 	-if 2 out of 3 ratio is available, then proceed
// 	-if not, then halt with error

//=======================================================

func setNPubs() {
	// set the nostr pubkeys for the participants

}

func coordinateNostrHandshake(session, key string, txRequest TxRequest) int {

	// Initialize retry counter and max retries
	maxRetries := 30
	ackHandshakeCount := 0
	retryCount := 0
	//var protoMessage ProtoMessage
	//var err error

	for retryCount < maxRetries {
		InitNostrHandshake(session, key, txRequest)
		time.Sleep(time.Second)

		newProtoMessage, err := nostrDownloadMessage(session, key)
		if err != nil {
			Logf("Error downloading message: %v", err)
			retryCount++
			time.Sleep(time.Second)
			continue
		} else {

			if newProtoMessage.Type == "ack_handshake" && newProtoMessage.SessionID == session && newProtoMessage.From != key {

				for _, item := range nostrHandShakeList {
					if item.SessionID == newProtoMessage.SessionID && newProtoMessage.Type == "ack_handshake" && newProtoMessage.From != key {
						if item.TxRequest == txRequest {
							fmt.Printf("Key: %s, Message: %+v\n", session, item)
							ackHandshakeCount++
							nostrHandShakeList = append(nostrHandShakeList, newProtoMessage)
						}
					}

				}
				// if !contains(nostrHandShakeList, newProtoMessage) {
				// 	//this is a new handshake
				// 	ackHandshakeCount++
				// 	nostrHandShakeList = append(nostrHandShakeList, newProtoMessage)
				// }
			}

			// for _, item := range nostrHandShakeList {
			// 	if item.SessionID == session && item.Type == "ack_handshake" && item.From != key {
			// 		if
			// 		fmt.Printf("Key: %s, Message: %+v\n", session, item)
			// 	}
			// }

			// protoMessage, ok :=
			// if !ok {
			// 	Logf("No handshake message in cache")
			// 	retryCount++
			// 	time.Sleep(time.Second)
			// 	continue
			// }
			// protoMessage, err = nostrDownloadMessage(session, key)
			// if err != nil {
			// 	Logf("Error downloading message (attempt %d/%d): %v", retryCount+1, maxRetries, err)
			// 	retryCount++
			// 	time.Sleep(time.Second)
			// 	continue
			// }
			// if ok {
			// 	protoMsg := protoMessage // No type assertion needed since protoMessage is already ProtoMessage type
			// 	if protoMsg.Type == "ack_handshake" && protoMsg.SessionID == session && protoMsg.From != key {
			// 		Logf("Ack handshake message received from %s", protoMsg.From)
			// 		ackHandshakeCount++
			// 		nostrHandShakeList[session] = protoMessage
			// 		//TODO: Start here also duplicate this code above

			// 	}

			retryCount++
			//Logf("Invalid ack handshake response (attempt %d/%d), retrying...", retryCount, maxRetries)
			time.Sleep(time.Second)
		}
	}
	return ackHandshakeCount
}

func AckNostrHandshake(session, key string, protoMessage ProtoMessage) {
	// handshake with the master
	keyShare, err := GetKeyShare(key)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	if protoMessage.Type == "init_handshake" && protoMessage.SessionID == session && protoMessage.From != key {
		Logf("init handshake message received from %s\n", protoMessage.From)
		Logf("sending ack handshake message to %s\n", key)
		//TODO: UI update - ask user to approve TX
		//if approved == true, send ack

		ackProtoMessage := ProtoMessage{
			SessionID:       session,
			Type:            "ack_handshake",
			From:            key,
			FromNostrPubKey: keyShare.LocalNostrPubKey,
			Recipients:      []NostrPartyPubKeys{{Peer: protoMessage.Master.MasterPeer, PubKey: protoMessage.Master.MasterPubKey}},
			Participants:    []string{key},
			Datetime:        time.Now().Format(time.RFC3339),
			RawMessage:      "",
			TxRequest:       protoMessage.TxRequest,
			Master:          Master{MasterPeer: protoMessage.Master.MasterPeer, MasterPubKey: protoMessage.Master.MasterPubKey},
		}

		// for _, peer := range protoMessage.Recipients {
		// 	if pubKey, ok := keyShare.NostrPartyPubKeys[peer.Party]; ok {
		// 		protoMessage.Recipients = append(protoMessage.Recipients, NostrPartyPubKeys{Party: peer.Party, PubKey: pubKey})
		// 	}
		// }
		nostrHandShakeList = append(nostrHandShakeList, ackProtoMessage)
		nostrSend(session, key, ackProtoMessage, "", "", "", "")
	}

}

func InitNostrHandshake(session, key string, txRequest TxRequest) {
	// handshake with the master
	keyShare, err := GetKeyShare(key)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	protoMessage := ProtoMessage{
		SessionID:       session,
		Type:            "init_handshake",
		From:            key,
		FromNostrPubKey: keyShare.LocalNostrPubKey,
		Recipients:      make([]NostrPartyPubKeys, 0, len(keyShare.NostrPartyPubKeys)),
		Datetime:        time.Now().Format(time.RFC3339),
		RawMessage:      "",
		TxRequest:       txRequest,
		Master:          Master{MasterPeer: keyShare.LocalPartyKey, MasterPubKey: keyShare.LocalNostrPubKey},
	}

	// Convert map to slice of NostrPartyPubKeys
	for party, pubKey := range keyShare.NostrPartyPubKeys {
		protoMessage.Recipients = append(protoMessage.Recipients, NostrPartyPubKeys{
			Peer:   party,
			PubKey: pubKey,
		})
	}

	nostrSend(session, key, protoMessage, "init_handshake", "", "", "")
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

// func nostrJoinSession(server, session, key string) error {
// 	nostrSend(session, key, "", "join_session", "", "", "")
// 	return nil
// }

// NOSTR Callback
func NostrListen(localParty string) {

	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}
	//masterPeer, masterPubKey := GetMaster(parties, localParty)

	// var isMaster bool
	// //var port string = "55055"

	// if masterPeer == keyShare.LocalPartyKey && masterPubKey == keyShare.LocalNostrPubKey {
	// 	// we are the master, so we start the host
	// 	isMaster = true
	// 	fmt.Printf("%s is master\n", localParty)
	// } else {
	// 	isMaster = false
	// }

	// if isMaster {
	// 	//RunRelay(port)
	// 	//fmt.Printf("relay started by %s\n", localParty)
	// 	//select {}
	// }

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
			//log.Printf("Parsed RawMessage: %+v\n", rawMessage)

			// Store the parsed raw message in cache using the session ID

			if protoMessage.Type == "init_handshake" {
				AckNostrHandshake(protoMessage.SessionID, localParty, protoMessage)
			} else {
				nostrMessageCache.Set(protoMessage.SessionID, protoMessage, cache.DefaultExpiration)
			}

		case <-globalCtx.Done():
			return

		case <-sub.EndOfStoredEvents:
			//fmt.Printf("Received all stored events, continuing to listen...\n")
		}
	}

}

func nostrSend(sessionID, key string, message ProtoMessage, messageType, fromParty, toParty, parties string) {

	// Initialize context if nil
	if globalCtx == nil {
		globalCtx = context.Background()
	}

	keyShare, err := GetKeyShare(key)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	protoMessageJSON, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshalling protoMessage: %v\n", err)
		return
	}

	for _, recipient := range message.Recipients {
		sharedSecret, err := nip04.ComputeSharedSecret(recipient.PubKey, keyShare.LocalNostrPrivKey)
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
			Tags:      nostr.Tags{{"p", recipient.PubKey}},
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
}

func nostrDownloadMessage(sessionID string, key string) (ProtoMessage, error) {
	msg, found := nostrMessageCache.Get(sessionID)
	if !found {
		return ProtoMessage{}, fmt.Errorf("message not found for session %s", sessionID)
	}
	protoMsg := msg.(ProtoMessage)
	//if protoMsg.To == key {
	return protoMsg, nil
	//}
	//return ProtoMessage{}, fmt.Errorf("message not found for session %s", sessionID)
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
