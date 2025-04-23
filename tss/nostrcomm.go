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
	nostrSessionList       []NostrSession
	nostrHandShakeList     []ProtoMessage
	nostrMessageCache      = cache.New(5*time.Minute, 10*time.Minute)
	globalRelay            *nostr.Relay
	globalCtx              context.Context
	nostrRelay             string = "ws://bbw-nostr.xyz"
	KeysignApprovalTimeout        = 3 * time.Second
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
	RawMessage      string              `json:"raw_message"`
	From            string              `json:"from"`
	To              string              `json:"to"`
	TxRequest       TxRequest           `json:"tx_request"`
	Master          Master              `json:"master"`
}

type NostrSession struct {
	Status       string    `json:"status"`
	SessionID    string    `json:"session_id"`
	Participants []string  `json:"participants"`
	Master       Master    `json:"master"`
	TxRequest    TxRequest `json:"tx_request"`
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
	DerivePath      string `json:"derive_path"`
	BtcPub          string `json:"btc_pub"`
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

func GetNostrPartyPubKeys(party string) (map[string]string, error) {
	keyShare, err := GetKeyShare(party)
	if err != nil {
		return nil, err
	}
	return keyShare.NostrPartyPubKeys, nil
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

func startKeysignMaster(sessionID string, participants []string, localParty string) {

	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	for i, item := range nostrSessionList {
		if item.SessionID == sessionID && item.Status == "pending" {
			nostrSessionList[i].Status = "start_keysign"

			recipients := make([]NostrPartyPubKeys, 0, len(participants))
			for _, participant := range participants {
				if participant != item.Master.MasterPeer { // Skip if participant is the master
					if pubKey, ok := keyShare.NostrPartyPubKeys[participant]; ok {
						recipients = append(recipients, NostrPartyPubKeys{
							Peer:   participant,
							PubKey: pubKey,
						})
					}
				}
			}

			startKeysignProtoMessage := ProtoMessage{
				SessionID:    sessionID,
				Type:         "start_keysign",
				From:         localParty,
				Recipients:   recipients,
				Participants: participants,
				RawMessage:   "",
				TxRequest:    item.TxRequest,
				Master:       Master{MasterPeer: item.Master.MasterPeer, MasterPubKey: item.Master.MasterPubKey},
			}
			nostrSend(sessionID, localParty, startKeysignProtoMessage, "", "", "")
		}
	}

}

func collectAckHandshake(sessionID, key string, protoMessage ProtoMessage) {
	for i, item := range nostrSessionList {
		if item.SessionID == sessionID && item.TxRequest == protoMessage.TxRequest {
			if !contains(item.Participants, protoMessage.From) {
				item.Participants = append(item.Participants, protoMessage.From)
				nostrSessionList[i] = item
				Logf("collected ack handshake from %s for session: %s", protoMessage.From, sessionID)
			}
		}
	}
}

func initNostrKeysignSession(sessionID string, participants []string, localParty string) {
	//This is only run by the master
	keyshareFile := localParty + ".ks"
	keyshare, err := os.ReadFile(keyshareFile)
	if err != nil {
		fmt.Printf("Error reading keyshare file for %s: %v\n", localParty, err)
		return
	}

	decodedKeyshare, err := base64.StdEncoding.DecodeString(string(keyshare))
	if err != nil {
		fmt.Printf("Go Error Decoding Base64: %v\n", err)
		return
	}

	var localState LocalState
	if err := json.Unmarshal(decodedKeyshare, &localState); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v\n", err)
		return
	}

	recipients := make([]NostrPartyPubKeys, 0, len(participants))
	for _, participant := range participants {
		if pubKey, ok := localState.NostrPartyPubKeys[participant]; ok {
			recipients = append(recipients, NostrPartyPubKeys{
				Peer:   participant,
				PubKey: pubKey,
			})
		}
	}

	for _, item := range nostrSessionList {
		if item.SessionID == sessionID { //Send to all participants except (self) master

			startKeysignMessage := ProtoMessage{
				SessionID:    sessionID,
				Type:         "start_keysign",
				From:         localParty,
				Recipients:   recipients,
				Participants: participants,
				RawMessage:   "",
				TxRequest:    item.TxRequest,
				Master:       Master{MasterPeer: item.Master.MasterPeer, MasterPubKey: item.Master.MasterPubKey},
			}
			nostrSend(sessionID, localParty, startKeysignMessage, "", "", "")
		}
	}

	// result, err := MpcSendBTC("", localParty, strings.Join(item.Participants, ","), sessionID, "", "", "", string(keyshare), item.TxRequest.DerivePath, item.TxRequest.BtcPub, item.TxRequest.SenderAddress, item.TxRequest.ReceiverAddress, int64(item.TxRequest.AmountSatoshi), int64(item.TxRequest.FeeSatoshi), "nostr")
	// if err != nil {
	// 	fmt.Printf("Go Error: %v\n", err)
	// } else {
	// 	fmt.Printf("\n [%s] Keysign Result %s\n", localParty, result)
	// }
	// break

}

func startNostrKeysignSession(sessionID string, participants []string, localParty string) {

	for i, item := range nostrSessionList {
		if item.SessionID == sessionID {

			nostrSessionList[i].Status = "start_keysign"
			nostrSessionList[i].Participants = participants

			keyshare, err := GetKeyShare(localParty)
			if err != nil {
				Logf("Error getting key share: %v", err)
				return
			}

			// Marshal the keyshare to JSON
			keyshareJSON, err := json.Marshal(keyshare)
			if err != nil {
				Logf("Error marshaling keyshare: %v", err)
				return
			}

			result, err := MpcSendBTC("", localParty, strings.Join(item.Participants, ","), sessionID, "", "", "", string(keyshareJSON), item.TxRequest.DerivePath, item.TxRequest.BtcPub, item.TxRequest.SenderAddress, item.TxRequest.ReceiverAddress, int64(item.TxRequest.AmountSatoshi), int64(item.TxRequest.FeeSatoshi), "nostr", "false")
			if err != nil {
				fmt.Printf("Go Error: %v\n", err)
			} else {
				fmt.Printf("\n [%s] Keysign Result %s\n", localParty, result)
			}
			//select {}
			// startKeysignMessage := ProtoMessage{
			// 	SessionID:       sessionID,
			// 	Type:            "start_keysign",
			// 	From:            localParty,
			// 	FromNostrPubKey: string(keyshare),
			// 	Recipients:      make([]NostrPartyPubKeys, 0, len(keyshare)),
			// 	Participants:    participants,
			// 	RawMessage:      "",
			// 	TxRequest:       item.TxRequest,
			// 	Master:          Master{MasterPeer: item.Master.MasterPeer, MasterPubKey: item.Master.MasterPubKey},
			// }
			// nostrSend(sessionID, localParty, startKeysignMessage, "", "", "")
		}
	}
}

func containsProtoMessage(list []ProtoMessage, msg ProtoMessage) bool {
	for _, element := range list {
		if element.Type == msg.Type &&
			element.SessionID == msg.SessionID &&
			element.From == msg.From {
			return true
		}
	}
	return false
}

func nostrSessionAlreadyExists(list []NostrSession, nostrSession NostrSession) bool {
	for _, element := range list {
		if element.SessionID == nostrSession.SessionID {
			return true
		}
	}
	return false
}

// func startNostrKeysignSession(SessionID string, participants []string, localParty string) {

// }

func initiateNostrHandshake(SessionID, key string, txRequest TxRequest) {

	// Initialize retry counter and max retries
	//maxRetries := 2
	//ackHandshakeCount := 0
	//retryCount := 0
	//var protoMessage ProtoMessage
	//var err error

	for _, session := range nostrSessionList {
		if session.SessionID == SessionID {
			// Found matching session
			Logf("Session already exists: %v", session)
			return
			//if session already exits, then skip everything and return session?
		}
	}

	keyShare, err := GetKeyShare(key)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	protoMessage := ProtoMessage{
		SessionID:       SessionID,
		Type:            "init_handshake",
		From:            key,
		FromNostrPubKey: keyShare.LocalNostrPubKey,
		Recipients:      make([]NostrPartyPubKeys, 0, len(keyShare.NostrPartyPubKeys)),
		RawMessage:      "",
		TxRequest:       txRequest,
		Master:          Master{MasterPeer: keyShare.LocalPartyKey, MasterPubKey: keyShare.LocalNostrPubKey},
	}

	// map nostrpartypubkeys
	for party, pubKey := range keyShare.NostrPartyPubKeys {
		protoMessage.Recipients = append(protoMessage.Recipients, NostrPartyPubKeys{
			Peer:   party,
			PubKey: pubKey,
		})
	}
	Logf("Sending init handshake message for SessionID: %s", SessionID)

	nostrSession := NostrSession{
		SessionID:    SessionID,
		Participants: []string{key},
		TxRequest:    protoMessage.TxRequest,
		Master:       protoMessage.Master,
		Status:       "pending",
	}

	if !nostrSessionAlreadyExists(nostrSessionList, nostrSession) {
		nostrSessionList = append(nostrSessionList, nostrSession)
	}

	//==============================SEND INIT_HANDSHAKE TO ALL NOSTRPUBKEYS========================
	nostrSend(SessionID, key, protoMessage, "", "", "")
	time.Sleep(time.Second * 1)
	//==============================ASSUME WE HAVE ALL ACK_HANDSHAKES==============================

	Logf("total nostrSessionList: %v", nostrSessionList)

	retryCount := 0
	maxRetries := 3
	sessionReady := false
	for retryCount < maxRetries {
		for _, item := range nostrSessionList {
			if item.SessionID == SessionID {

				partyCount := len(keyShare.NostrPartyPubKeys)
				participantCount := len(item.Participants)

				if participantCount/partyCount >= 2/3 {
					Logf("We have 2/3 of participants approved , sending (start_keysign) for session: %s", SessionID)
					sessionReady = true
					//=================send start_keysign to all participants=====================
					startKeysignMaster(SessionID, item.Participants, key)
					//initNostrKeysignSession(SessionID, item.Participants, key)
				} else {
					Logf("We do not have 2/3 of participants approved yet for session: %s", SessionID)
					Logf("Waiting for 3 seconds before retrying")
					time.Sleep(KeysignApprovalTimeout)
				}
			}
		}
		if sessionReady {
			break
		}
		retryCount++
		if retryCount >= maxRetries {
			Logf("Max retries reached, giving up on session: %s", SessionID)
			return
		}
	}

}

func AckNostrHandshake(session, key string, protoMessage ProtoMessage) {
	// send handshake to master
	keyShare, err := GetKeyShare(key)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	Logf("init handshake message received from %s\n", protoMessage.From)
	Logf("sending ack handshake message to %s\n", key)
	//TODO: UI update - ask user to approve TX
	//if approved == true, send ack
	//If approved, then status="pending"
	//If not approved, then status="rejected"

	//===================USER APPROVED TX======================
	nostrSession := NostrSession{
		SessionID:    session,
		Participants: []string{key},
		TxRequest:    protoMessage.TxRequest,
		Master:       protoMessage.Master,
		Status:       "pending",
	}

	if !nostrSessionAlreadyExists(nostrSessionList, nostrSession) {
		nostrSessionList = append(nostrSessionList, nostrSession)
	}

	ackProtoMessage := ProtoMessage{
		SessionID:       session,
		Type:            "ack_handshake",
		From:            key,
		FromNostrPubKey: keyShare.LocalNostrPubKey,
		Recipients:      []NostrPartyPubKeys{{Peer: protoMessage.Master.MasterPeer, PubKey: protoMessage.Master.MasterPubKey}},
		Participants:    []string{key},
		RawMessage:      "",
		TxRequest:       protoMessage.TxRequest,
		Master:          Master{MasterPeer: protoMessage.Master.MasterPeer, MasterPubKey: protoMessage.Master.MasterPubKey},
	}

	nostrSend(session, key, ackProtoMessage, "", "", "")

	// for _, peer := range protoMessage.Recipients {
	// 	if pubKey, ok := keyShare.NostrPartyPubKeys[peer.Peer]; ok {
	// 		protoMessage.Recipients = append(protoMessage.Recipients, NostrPartyPubKeys{Peer: peer.Peer, PubKey: pubKey})
	// 	}
	// }
	// if !containsProtoMessage(nostrHandShakeList, ackProtoMessage) {
	// 	nostrHandShakeList = append(nostrHandShakeList, ackProtoMessage)
	// 	nostrSend(session, key, ackProtoMessage, "", "", "")
	// }

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
		//Datetime:        time.Now().Format(time.RFC3339),
		RawMessage: "",
		TxRequest:  txRequest,
		Master:     Master{MasterPeer: keyShare.LocalPartyKey, MasterPubKey: keyShare.LocalNostrPubKey},
	}

	// Convert map to slice of NostrPartyPubKeys
	for party, pubKey := range keyShare.NostrPartyPubKeys {
		protoMessage.Recipients = append(protoMessage.Recipients, NostrPartyPubKeys{
			Peer:   party,
			PubKey: pubKey,
		})
	}

	nostrSend(session, key, protoMessage, "", "", "")
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
	// Add recovery from panics
	// defer func() {
	// 	if r := recover(); r != nil {
	// 		log.Printf("Recovered from panic in NostrListen: %v", r)
	// 		// Restart the listener after a delay
	// 		time.Sleep(5 * time.Second)
	// 		go NostrListen(localParty)
	// 	}
	// }()

	keyShare, err := GetKeyShare(localParty)
	if err != nil {
		log.Printf("Error getting key share: %v\n", err)
		return
	}

	// Validate the public key format
	if !nostr.IsValidPublicKey(keyShare.LocalNostrPubKey) {
		log.Printf("Invalid public key format\n")
		return
	}

	if err := validateKeys(keyShare.LocalNostrPrivKey, keyShare.LocalNostrPubKey); err != nil {
		log.Printf("Key validation error: %v\n", err)
		return
	}

	// Main connection loop with retry

	globalCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var relayErr error
	globalRelay, relayErr = nostr.RelayConnect(globalCtx, nostrRelay)
	if relayErr != nil {
		log.Printf("Error connecting to relay: %v\n", relayErr)
		return
	}
	defer globalRelay.Close()

	cutoffTime := time.Now().Add(-15 * time.Second)
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
	// Event processing loop
	for {
		select {
		case event := <-sub.Events:
			sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, keyShare.LocalNostrPrivKey)
			if err != nil {
				log.Printf("Error computing shared secret: %v\n", err)
				continue
			}

			decryptedMessage, err := nip04.Decrypt(event.Content, sharedSecret)
			if err != nil {
				log.Printf("Error decrypting message: %v\n", err)
				continue
			}

			var protoMessage ProtoMessage
			if err := json.Unmarshal([]byte(decryptedMessage), &protoMessage); err != nil {
				log.Printf("Error parsing decrypted message: %v\n", err)
				continue
			}

			if protoMessage.Type == "init_handshake" && protoMessage.From != localParty { //only non-masters should run this
				AckNostrHandshake(protoMessage.SessionID, localParty, protoMessage)
				//continue
			}

			if protoMessage.Type == "ack_handshake" && protoMessage.From != localParty {
				if protoMessage.Master.MasterPeer == localParty { //Only master should run this
					collectAckHandshake(protoMessage.SessionID, localParty, protoMessage)
					//continue
				}
			}

			if protoMessage.Type == "start_keysign" && protoMessage.From != localParty { //non-masters should run this
				Logf("start_keysign recieved from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
				startNostrKeysignSession(protoMessage.SessionID, protoMessage.Participants, localParty)
				//startKeysignMaster(protoMessage.SessionID, protoMessage.Participants, localParty)

				//continue
			}

			if protoMessage.Type == "keysign" {
				Logf("keysign recieved from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
				nostrMessageCache.Set(protoMessage.SessionID, protoMessage, cache.DefaultExpiration)
				continue
			}

		case <-globalCtx.Done():
			log.Printf("Context cancelled, reconnecting...")
			return

		case <-sub.EndOfStoredEvents:
			// Continue listening for new events
			continue
		}
	}

}

func nostrSend(sessionID, key string, message ProtoMessage, fromParty, toParty, parties string) {

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

	//sessionID = sessionID[:len(sessionID)-1]
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

// Default
// - All parties start nostrListen
// - if "type=init_handshake" is detected, ask user to approve

// 	protoMessage := ProtoMessage{
// 		SessionID:       session,
// 		Type:            "init_handshake",
// 		From:            key,
// 		FromNostrPubKey: keyShare.LocalNostrPubKey,
// 		Recipients:      make([]NostrPartyPubKeys, 0, len(keyShare.NostrPartyPubKeys)),
// 		RawMessage: "",
// 		TxRequest:  txRequest,
// 		Master:     Master{MasterPeer: keyShare.LocalPartyKey, MasterPubKey: keyShare.LocalNostrPubKey},
// 	}

// - if approved, send back "ack_handshake" to the master (master is the one who sends the "type=init_handshake")

// 		ackProtoMessage := ProtoMessage{
// 			SessionID:       session,
// 			Type:            "ack_handshake",
// 			From:            key,
// 			FromNostrPubKey: keyShare.LocalNostrPubKey,
// 			Recipients:      []NostrPartyPubKeys{{Peer: protoMessage.Master.MasterPeer, PubKey: protoMessage.Master.MasterPubKey}},
// 			Participants:    []string{key},
// 			RawMessage: "",
// 			TxRequest:  protoMessage.TxRequest,
// 			Master:     Master{MasterPeer: protoMessage.Master.MasterPeer, MasterPubKey: protoMessage.Master.MasterPubKey},
// 		}

// MASTER
// - recives and stores ack_handshakes in nostrHandShakeList, makes sure the session details match the "init_handshake"
// - prevents duplicates
// - waits for 20 seconds???
// - if 2/3 of participants approve/respond, master sends "type=start_keysign" with startNostrSession to all participants who approved

// 	for _, item := range nostrSessionList {
// 		if item.SessionID == sessionID {

// 			startKeysignMessage := ProtoMessage{
// 				SessionID:       sessionID,
// 				Type:            type_session,
// 				From:            localParty,
// 				FromNostrPubKey: string(keyshare),
// 				Recipients:      make([]NostrPartyPubKeys, 0, len(keyshare)),
// 				Participants:    participants,
// 				RawMessage:      "",
// 				TxRequest:       item.TxRequest,
// 				Master:          Master{MasterPeer: item.Master.MasterPeer, MasterPubKey: item.Master.MasterPubKey},
// 			}
// 			nostrSend(sessionID, localParty, startKeysignMessage, type_session, "", "", "")
// 		}
// 	}

// 	The following line is not being hit, this is the problem.
// 						nostrMessageCache.Set(protoMessage.SessionID, protoMessage, cache.DefaultExpiration)

// 	Also why is func (m *MessengerImp) Send being run twice from peer1 to peer2?

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
