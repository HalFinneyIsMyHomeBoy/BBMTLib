package tss

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/patrickmn/go-cache"
)

// Global variables
var (
	nostrSessionList          []NostrSession
	nostrPingList             []ProtoMessage
	nostrMessageCache         = cache.New(5*time.Minute, 10*time.Minute)
	relay                     *nostr.Relay
	globalCtx, _              = context.WithCancel(context.Background())
	KeysignApprovalTimeout    = 4 * time.Second
	KeysignApprovalMaxRetries = 30
	nostrMutex                sync.Mutex
	chunkCache                = cache.New(5*time.Minute, 10*time.Minute)
	chunkMutex                sync.Mutex
	localState                LocalState
	localNostrKeys            NostrKeys
	globalLocalNostrKeys      NostrKeys
	globalLocalTesting        bool
	nostrListenCancel         context.CancelFunc
)

type ProtoMessage struct {
	FunctionType    string    `json:"function_type"`
	MessageType     string    `json:"message_type"`
	Participants    []string  `json:"participants"`
	Recipients      []string  `json:"recipients"`
	FromNostrPubKey string    `json:"from_nostr_pubkey"`
	PartyNpubs      []string  `json:"party_npubs"`
	SessionID       string    `json:"sessionID"`
	ChainCode       string    `json:"chain_code"`
	RawMessage      []byte    `json:"raw_message"`
	SeqNo           string    `json:"seq_no"`
	From            string    `json:"from"`
	To              string    `json:"to"`
	TxRequest       TxRequest `json:"tx_request"`
	Master          Master    `json:"master"`
	SessionKey      string    `json:"session_key"`
}

type NostrSession struct {
	Status       string    `json:"status"`
	SessionID    string    `json:"session_id"`
	ChainCode    string    `json:"chain_code"`
	SessionKey   string    `json:"session_key"`
	Participants []string  `json:"participants"`
	Master       Master    `json:"master"`
	TxRequest    TxRequest `json:"tx_request"`
}

type NostrKeys struct {
	LocalNostrPubKey  string   `json:"local_nostr_pub_key"`
	LocalNostrPrivKey string   `json:"local_nostr_priv_key"`
	NostrPartyPubKeys []string `json:"nostr_party_pub_keys"`
}

type Master struct {
	MasterPeer   string `json:"master_peer"`
	MasterPubKey string `json:"master_pubkey"`
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

const (
	// Two days in seconds for randomizing created_at
	TWO_DAYS  = 2 * 24 * 60 * 60
	TWO_HOURS = 2 * 60 * 60
)

// Rumor represents a kind:14 rumor (unsigned chat message)
type Rumor struct {
	nostr.Event
	ID string
}

// ChunkedMessage represents a chunk of a larger message
type ChunkedMessage struct {
	TotalChunks int    `json:"total_chunks"`
	ChunkIndex  int    `json:"chunk_index"`
	MessageID   string `json:"message_id"`
	Data        string `json:"data"`
}

// MessageChunks holds the chunks of a message being reassembled
type MessageChunks struct {
	TotalChunks int
	Chunks      []string
	Complete    bool
}

// Helper function to get current UNIX timestamp
func now() nostr.Timestamp {
	return nostr.Timestamp(time.Now().Unix())
}

func randomSeed(length int) string {
	const characters = "0123456789abcdef"
	result := make([]byte, length)
	rand.Read(result)
	for i := 0; i < length; i++ {
		result[i] = characters[int(result[i])%len(characters)]
	}
	return string(result)
}

// CreateRumor creates a kind:14 rumor (unsigned chat message)
func createRumor(content string, senderPubkey string, recipientPubkey string) Rumor {
	rumor := Rumor{
		Event: nostr.Event{
			Kind:      14, // NIP-17 kind for chat messages
			CreatedAt: nostr.Now(),
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
		CreatedAt: nostr.Now(),
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
		CreatedAt: nostr.Now(),
		Content:   encryptedContent,
		Tags:      nostr.Tags{{"p", recipientPubkey}},
	}
	// Sign the gift wrap
	if err := wrap.Sign(randomKey); err != nil {
		return nil, fmt.Errorf("failed to sign wrap: %w", err)
	}
	return wrap, nil
}

func GetNostrKeys(party string) (NostrKeys, error) {

	data, err := os.ReadFile(party + ".nostr")
	if err != nil {
		fmt.Printf("Go Error GetNostrKeys: %v", err)
	}

	var nostrKeys NostrKeys
	if err := json.Unmarshal(data, &nostrKeys); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v", err)
	}

	return nostrKeys, nil
}

func NostrListen(localNpub, localNsec, nostrRelay string) {
	ctx, cancel := context.WithCancel(context.Background())
	nostrListenCancel = cancel
	defer func() { nostrListenCancel = nil }()

	// Store the localNostrKeys in the global variable so other functions can access it
	globalLocalNostrKeys = NostrKeys{
		LocalNostrPubKey:  localNpub,
		LocalNostrPrivKey: localNsec,
	}

	// Decode recipient's private key
	_, recipientPrivkey, err := nip19.Decode(globalLocalNostrKeys.LocalNostrPrivKey)
	if err != nil {
		log.Printf("Error decoding recipient nsec: %v", err)
		return
	}
	recipientPubkey, err := nostr.GetPublicKey(recipientPrivkey.(string))
	if err != nil {
		log.Printf("Error deriving recipient pubkey: %v", err)
		return
	}

	retryInterval := 10 * time.Second
	backoff := retryInterval

	for {
		// Check if we should stop
		select {
		case <-ctx.Done():
			log.Printf("NostrListen stopped by cancel")
			return
		default:
		}
		// Create a new context for this connection attempt
		ctxLoop, cancelLoop := context.WithCancel(ctx)

		// Connect to relay
		relay, err = nostr.RelayConnect(ctxLoop, nostrRelay)
		if err != nil {
			log.Printf("Connection failed: %v, retrying in %v...\n", err, backoff)
			cancelLoop()
			time.Sleep(backoff)
			// Exponential backoff with max of 30 seconds
			backoff = time.Duration(math.Min(float64(backoff*2), 30)) * time.Second
			continue
		}

		// Reset backoff on successful connection
		backoff = retryInterval

		since := nostr.Timestamp(time.Now().Add(-10 * time.Second).Unix())

		filters := []nostr.Filter{{
			Kinds: []int{1059}, // Subscribe to NIP-44 messages
			Tags:  map[string][]string{"p": {recipientPubkey}},
			Since: &since,
		}}

		sub, err := relay.Subscribe(ctxLoop, filters)
		if err != nil {
			log.Printf("Subscription failed: %v, retrying in %v...\n", err, backoff)
			cancelLoop()
			time.Sleep(backoff)
			continue
		}

		log.Printf("%s subscribed to nostr\n", globalLocalNostrKeys.LocalNostrPubKey)

		// Create a channel to signal when we need to reconnect
		reconnect := make(chan struct{})

		// Start a goroutine to handle events
		go func() {
			for {
				select {
				case event := <-sub.Events:
					if event == nil {
						log.Printf("Connection lost, triggering reconnect...\n")
						close(reconnect)
						return
					}

					if err := processNostrEvent(event, recipientPrivkey.(string), globalLocalNostrKeys.LocalNostrPubKey); err != nil {
						log.Printf("Error processing event: %v", err)
					}

				case <-ctxLoop.Done():
					log.Printf("Context cancelled, triggering reconnect...\n")
					close(reconnect)
					return

				case <-sub.EndOfStoredEvents:
					continue
				}
			}
		}()

		// Wait for reconnect signal
		<-reconnect
		cancelLoop()

		// Clean up the subscription
		sub.Unsub()

		// Small delay before reconnecting
		time.Sleep(backoff)
	}
}

func processNostrEvent(event *nostr.Event, recipientPrivkey string, localParty string) error {
	var decryptedContent string

	// Handle different event kinds
	if event.Kind == 1059 {

		conversationKey, err := nip44.GenerateConversationKey(event.PubKey, recipientPrivkey)
		if err != nil {
			return fmt.Errorf("failed to generate conversation key: %v", err)
		}

		// Decrypt gift wrap content (kind:1059)
		sealJSON, err := nip44.Decrypt(event.Content, conversationKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt gift wrap: %v", err)
		}

		// Deserialize seal
		var seal nostr.Event
		if err := json.Unmarshal([]byte(sealJSON), &seal); err != nil {
			return fmt.Errorf("failed to deserialize seal: %v", err)
		}

		// Generate conversation key for seal
		sealConversationKey, err := nip44.GenerateConversationKey(seal.PubKey, recipientPrivkey)
		if err != nil {
			return fmt.Errorf("failed to generate seal conversation key: %v", err)
		}

		// Decrypt seal content (kind:13)
		rumorJSON, err := nip44.Decrypt(seal.Content, sealConversationKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt seal: %v", err)
		}

		// Deserialize rumor
		var rumor Rumor
		if err := json.Unmarshal([]byte(rumorJSON), &rumor); err != nil {
			return fmt.Errorf("failed to deserialize rumor: %v", err)
		}
		decryptedContent = rumor.Content
	} else {
		return fmt.Errorf("unsupported event kind: %d", event.Kind)
	}

	// Check if this is a chunked message
	var chunkedMsg ChunkedMessage
	if err := json.Unmarshal([]byte(decryptedContent), &chunkedMsg); err == nil && chunkedMsg.MessageID != "" {
		// This is a chunked message, handle reassembly
		completeMessage, err := handleChunkedMessage(chunkedMsg)
		if err != nil {
			return fmt.Errorf("failed to handle chunked message: %w", err)
		}
		if completeMessage == "" {
			// Message is not yet complete
			return nil
		}
		decryptedContent = completeMessage
	}

	var protoMessage ProtoMessage
	if err := json.Unmarshal([]byte(decryptedContent), &protoMessage); err != nil {
		return fmt.Errorf("parse message: %w", err)
	}

	if protoMessage.From == localParty {
		return nil // Ignore messages from self
	}

	if protoMessage.FunctionType == "ping" {
		go returnNostrPong(localParty, protoMessage)
		return nil
	}

	if protoMessage.FunctionType == "pong" {
		// Check if this pong corresponds to a ping we sent
		for i, ping := range nostrPingList {
			if string(ping.RawMessage) == string(protoMessage.RawMessage) {
				// Remove the ping from the list once we get a response
				nostrPingList[i].FunctionType = "pong"
			}
		}
		return nil
	}

	if protoMessage.FunctionType == "init_handshake" {
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.FunctionType == "ack_handshake" {
		if protoMessage.Master.MasterPeer == localParty {
			collectAckHandshake(protoMessage.SessionID, protoMessage)
		}
	}

	if protoMessage.FunctionType == "start_keysign" && protoMessage.MessageType != "message" {
		Logf("start_keysign received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.FunctionType == "keygen" && protoMessage.MessageType != "message" {
		Logf("start_keygen received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.MessageType == "message" {
		Logf("message received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		key := protoMessage.MessageType + "-" + protoMessage.SessionID
		nostrMutex.Lock()
		nostrSetData(key, &protoMessage)
		nostrMutex.Unlock()
	}

	return nil
}

func handleChunkedMessage(chunk ChunkedMessage) (string, error) {
	chunkMutex.Lock()
	defer chunkMutex.Unlock()

	// Get or create message chunks
	var chunks *MessageChunks
	if value, found := chunkCache.Get(chunk.MessageID); found {
		chunks = value.(*MessageChunks)
	} else {
		chunks = &MessageChunks{
			TotalChunks: chunk.TotalChunks,
			Chunks:      make([]string, chunk.TotalChunks),
		}
		chunkCache.Set(chunk.MessageID, chunks, cache.DefaultExpiration)
	}

	// Store the chunk
	chunks.Chunks[chunk.ChunkIndex] = chunk.Data

	// Check if all chunks are received
	complete := true
	for _, c := range chunks.Chunks {
		if c == "" {
			complete = false
			break
		}
	}

	if complete {
		// Combine all chunks
		completeMessage := strings.Join(chunks.Chunks, "")
		// Clean up the cache
		chunkCache.Delete(chunk.MessageID)
		return completeMessage, nil
	}

	return "", nil
}

func NostrKeygen(relay, localNsec, localNpub, partyNpubs, verbose string) (string, error) {

	go NostrListen(localNpub, localNsec, relay)
	time.Sleep(2 * time.Second)

	// Find the master npub (peer with largest npub value)
	peers := strings.Split(partyNpubs, ",")
	masterNpub := peers[0]
	for _, npub := range peers[1:] {
		if npub > masterNpub {
			masterNpub = npub
		}
	}

	if masterNpub == localNpub { //If we are the master, we need to initiate the handshake
		txRequest := TxRequest{}    //Empty TxRequest because it's a keygen, not a keysign
		sessionID := randomSeed(64) //Master generates the sessionID, SessionKey and chaincode
		sessionKey := randomSeed(64)
		chainCode := randomSeed(64)

		//Set the globalLocalNostrKeys
		globalLocalNostrKeys.NostrPartyPubKeys = strings.Split(partyNpubs, ",")
		globalLocalNostrKeys.LocalNostrPrivKey = localNsec
		globalLocalNostrKeys.LocalNostrPubKey = localNpub

		initiateNostrHandshake(sessionID, chainCode, sessionKey, localNpub, partyNpubs, "keygen", txRequest)
		Logf("Starting Master Keygen for session: %s", sessionID)

		ppmFile := localNpub + ".json"

		result, err := JoinKeygen(ppmFile, localNpub, partyNpubs, "", "", sessionID, "", chainCode, sessionKey, "nostr")
		if err != nil {
			fmt.Printf("Go Error: %v", err)
		} else {
			fmt.Printf("\n [%s] Keygen Result %s\n", localNpub, result)
		}

	} else {
		//If we are not the master, we need to join the keygen

		//Set the globalLocalNostrKeys
		globalLocalNostrKeys.NostrPartyPubKeys = strings.Split(partyNpubs, ",")
		globalLocalNostrKeys.LocalNostrPrivKey = localNsec
		globalLocalNostrKeys.LocalNostrPubKey = localNpub

		sessions, err := WaitForSessions()
		if err != nil {
			return "", fmt.Errorf("error getting sessions: %v", err)
		} else {

			protoMessage := ProtoMessage{
				SessionID:       sessions[0].SessionID,
				ChainCode:       sessions[0].ChainCode,
				SessionKey:      sessions[0].SessionKey,
				TxRequest:       sessions[0].TxRequest,
				Master:          sessions[0].Master,
				FunctionType:    "ack_handshake",
				From:            localNpub,
				FromNostrPubKey: localNpub,
				Recipients:      []string{sessions[0].Master.MasterPubKey},
				Participants:    []string{localNpub},
			}
			AckNostrHandshake(protoMessage, localNpub)

			Logf("Joining Keygen for session: %s", sessions[0].SessionID)
			ppmFile := localNpub + ".json"

			result, err := JoinKeygen(ppmFile, localNpub, partyNpubs, "", "", sessions[0].SessionID, "", sessions[0].ChainCode, sessions[0].SessionKey, "nostr")
			if err != nil {
				fmt.Printf("Go Error: %v", err)
			} else {
				return result, nil
			}
		}
	}

	return "", nil
}

// WaitForSessions polls GetSessions() every second for up to 2 minutes until it returns a non-empty result
func WaitForSessions() ([]NostrSession, error) {
	for i := 0; i < 120; i++ { // 2 minutes = 120 seconds
		sessions, err := GetSessions()
		if err != nil {
			return nil, err
		}
		if len(sessions) > 0 {
			return sessions, nil
		}
		time.Sleep(1 * time.Second)
		Logf("Waiting for sessions...")
	}
	return nil, fmt.Errorf("timeout waiting for sessions")
}

func initiateNostrHandshake(SessionID, chainCode, sessionKey, localParty, partyNpubs, functionType string, txRequest TxRequest) (bool, error) {

	peers := strings.Split(partyNpubs, ",")
	globalLocalNostrKeys.NostrPartyPubKeys = peers

	protoMessage := ProtoMessage{
		SessionID:       SessionID,
		ChainCode:       chainCode,
		SessionKey:      sessionKey,
		FunctionType:    "init_handshake",
		From:            localParty,
		FromNostrPubKey: globalLocalNostrKeys.LocalNostrPubKey,
		Recipients:      peers,
		PartyNpubs:      peers,
		TxRequest:       txRequest,
		Master:          Master{MasterPeer: localParty, MasterPubKey: globalLocalNostrKeys.LocalNostrPubKey},
	}

	nostrSession := NostrSession{
		SessionID:    SessionID,
		Participants: []string{localParty},
		TxRequest:    protoMessage.TxRequest,
		Master:       protoMessage.Master,
		Status:       "pending",
		SessionKey:   sessionKey,
		ChainCode:    chainCode,
	}

	if !nostrSessionAlreadyExists(nostrSessionList, nostrSession) {
		nostrSessionList = append(nostrSessionList, nostrSession)
	}

	//==============================SEND (INIT_HANDSHAKE) TO ALL PARTIES========================
	Logf("Sending (init_handshake) message for SessionID: %s", SessionID)
	nostrSend(protoMessage)
	//==============================COLLECT ACK_HANDSHAKES==============================

	partyCount := len(globalLocalNostrKeys.NostrPartyPubKeys)
	retryCount := 0
	maxRetries := KeysignApprovalMaxRetries
	sessionReady := false
	for retryCount <= maxRetries {
		for _, item := range nostrSessionList {
			if item.SessionID == SessionID {

				if functionType == "keygen" {
					participantCount := len(item.Participants)

					if participantCount == partyCount {
						Logf("All participants have approved, sending %s for session: %s", functionType, SessionID)
						sessionReady = true
						startSessionMaster(SessionID, item.Participants, localParty, functionType)
					}
				} else {
					participantCount := len(item.Participants)
					participationRatio := float64(participantCount) / float64(partyCount)

					if participationRatio >= 0.66 {
						Logf("Enough participants have approved, sending %s for session: %s", functionType, SessionID)
						if item.Status == "pending" {
							sessionReady = true
							startSessionMaster(SessionID, item.Participants, localParty, functionType)
						} else {
							return false, fmt.Errorf("session not ready")
						}
						return sessionReady, nil
					} else {
						if retryCount >= maxRetries {

							participationRatio := float64(participantCount) / float64(partyCount)

							if participationRatio >= 0.66 {

								Logf("We have 2/3 of participants approved, sending %s for session: %s", functionType, SessionID)
								sessionReady = true
								startSessionMaster(SessionID, item.Participants, localParty, functionType)
							} else {
								Logf("Max retries reached, giving up on session: %s", SessionID)
								return false, fmt.Errorf("max retries reached")
							}
						} else {
							Logf("Waiting before retrying")
							time.Sleep(KeysignApprovalTimeout)
						}
					}
				}
			}
		}
		if sessionReady {
			break
		}
		retryCount++
	}
	return sessionReady, nil
}

func collectAckHandshake(sessionID string, protoMessage ProtoMessage) {

	for i, item := range nostrSessionList {
		if item.SessionID == sessionID && item.TxRequest == protoMessage.TxRequest {
			if !contains(item.Participants, protoMessage.From) {
				item.Participants = append(item.Participants, protoMessage.From)
				nostrSessionList[i] = item
				Logf("%s has approved session: %s", protoMessage.From, sessionID)
				Logf("%v out of %v participants have approved", int(len(item.Participants)), int(len(globalLocalNostrKeys.NostrPartyPubKeys)))
			}
		}
	}
}

func AckNostrHandshake(protoMessage ProtoMessage, localParty string) {
	// send handshake to master

	Logf("(init_handshake) message received from %s\n", protoMessage.Master.MasterPeer)
	Logf("Collected ack handshake from %s for session: %s", protoMessage.Master.MasterPeer, protoMessage.SessionID)
	Logf("sending (ack_handshake) message to %s\n", protoMessage.Master.MasterPeer)

	nostrSession := NostrSession{
		SessionID:    protoMessage.SessionID,
		Participants: []string{localParty},
		TxRequest:    protoMessage.TxRequest,
		Master:       protoMessage.Master,
		Status:       "pending",
		SessionKey:   protoMessage.SessionKey,
		ChainCode:    protoMessage.ChainCode,
	}

	if !contains(nostrSession.Participants, nostrSession.Master.MasterPeer) {
		nostrSession.Participants = append(nostrSession.Participants, nostrSession.Master.MasterPeer)
	}

	if !nostrSessionAlreadyExists(nostrSessionList, nostrSession) {
		nostrSessionList = append(nostrSessionList, nostrSession)
	}

	ackProtoMessage := ProtoMessage{
		SessionID:       nostrSession.SessionID,
		ChainCode:       nostrSession.ChainCode,
		SessionKey:      nostrSession.SessionKey,
		FunctionType:    "ack_handshake",
		From:            localParty,
		FromNostrPubKey: nostrSession.Master.MasterPubKey,
		Recipients:      []string{nostrSession.Master.MasterPeer},
		Participants:    []string{localParty},
		TxRequest:       nostrSession.TxRequest,
		Master:          nostrSession.Master,
	}
	nostrSend(ackProtoMessage)

}

func startSessionMaster(sessionID string, participants []string, localParty string, functionType string) {

	for i, item := range nostrSessionList {
		if item.SessionID == sessionID && item.Status == "pending" {
			nostrSessionList[i].Status = functionType

			recipients := make([]string, 0, len(participants))
			for _, participant := range participants {
				if participant != item.Master.MasterPeer { // Skip if participant is the master
					recipients = append(recipients, participant)
				}
			}

			startKeysignProtoMessage := ProtoMessage{
				SessionID:    sessionID,
				ChainCode:    item.ChainCode,
				SessionKey:   item.SessionKey,
				FunctionType: functionType,
				From:         localParty,
				Recipients:   recipients,
				Participants: participants,
				TxRequest:    item.TxRequest,
				Master:       Master{MasterPeer: item.Master.MasterPeer, MasterPubKey: item.Master.MasterPubKey},
			}
			nostrSend(startKeysignProtoMessage)
		}
	}
}

func startPartyNostrSpend(sessionID string, participants []string, localParty string, keyShare LocalState) {

	for i, item := range nostrSessionList {
		if item.SessionID == sessionID {

			nostrSessionList[i].Status = "start_keysign"
			nostrSessionList[i].Participants = participants
			sessionKey := nostrSessionList[i].SessionKey

			if globalLocalTesting {
				var err error
				keyShare, err = GetKeyShare(localParty)
				if err != nil {
					Logf("Error getting keyshare: %v", err)
					return
				}
			}

			keyShareJSON, err := json.Marshal(keyShare)
			if err != nil {
				Logf("Error marshaling keyshare: %v", err)
				return
			}

			peers := strings.Join(item.Participants, ",")

			result, err := MpcSendBTC("", localParty, peers, sessionID, sessionKey, "", "", string(keyShareJSON), item.TxRequest.DerivePath, item.TxRequest.BtcPub, item.TxRequest.SenderAddress, item.TxRequest.ReceiverAddress, int64(item.TxRequest.AmountSatoshi), int64(item.TxRequest.FeeSatoshi), "nostr", "false")
			if err != nil {
				fmt.Printf("Go Error: %v", err)
			} else {
				fmt.Printf("\n [%s] Keysign Result %s\n", localParty, result)
			}
		}
	}
}

func nostrFlagPartyKeysignComplete(sessionID string) error {
	for i := len(nostrSessionList) - 1; i >= 0; i-- {
		if nostrSessionList[i].SessionID == sessionID {
			nostrSessionList[i].Status = "keysign_complete"
		}
	}
	Logf("Nostr Keysign Complete: %s", sessionID)
	return nil
}

func nostrFlagPartyKeygenComplete(sessionID string) error {
	for i := len(nostrSessionList) - 1; i >= 0; i-- {
		if nostrSessionList[i].SessionID == sessionID {
			nostrSessionList[i].Status = "keygen_complete"
		}
	}
	Logf("Nostr Keygen Complete: %s", sessionID)
	return nil
}

func nostrDeleteSession(sessionID string) {
	for i := len(nostrSessionList) - 1; i >= 0; i-- {
		if nostrSessionList[i].SessionID == sessionID {
			nostrSessionList = append(nostrSessionList[:i], nostrSessionList[i+1:]...)
		}
	}
	Logf("Nostr Session Deleted: %s", sessionID)
}

func nostrSessionAlreadyExists(list []NostrSession, nostrSession NostrSession) bool {

	for _, element := range list {
		if element.SessionID == nostrSession.SessionID {
			return true
		}
	}
	return false
}

func nostrSend(protoMessage ProtoMessage) error {

	for _, recipient := range protoMessage.Recipients {
		protoMessageJSON, err := json.Marshal(protoMessage)
		if err != nil {
			log.Printf("Error marshalling protoMessage: %v", err)
			return err
		}

		protoMessageSize := int64(len(protoMessageJSON))
		var event *nostr.Event

		if protoMessageSize > 26*1024 { //If data is larger than 64KB, break into chunks otherwise NIP-44 won't support it

			// Decode sender's private key and recipient's public key
			_, senderPrivkey, err := nip19.Decode(globalLocalNostrKeys.LocalNostrPrivKey)
			if err != nil {
				return fmt.Errorf("invalid sender nsec: %w", err)
			}
			senderPubkey, err := nostr.GetPublicKey(senderPrivkey.(string))
			if err != nil {
				return fmt.Errorf("failed to derive sender pubkey: %w", err)
			}
			_, recipientPubkey, err := nip19.Decode(recipient)
			if err != nil {
				return fmt.Errorf("invalid recipient npub: %w", err)
			}

			// Generate a unique message ID for this chunked message
			messageID := fmt.Sprintf("%s-%d", protoMessage.SessionID, time.Now().UnixNano())

			// Split message into chunks smaller than 64KB
			chunkSize := 26 * 1024
			totalChunks := int(math.Ceil(float64(protoMessageSize) / float64(chunkSize)))
			messageStr := string(protoMessageJSON)

			for i := 0; i < totalChunks; i++ {
				start := i * chunkSize
				end := int(math.Min(float64((i+1)*chunkSize), float64(protoMessageSize)))
				chunk := messageStr[start:end]

				// Create chunked message
				chunkedMsg := ChunkedMessage{
					TotalChunks: totalChunks,
					ChunkIndex:  i,
					MessageID:   messageID,
					Data:        chunk,
				}

				// Marshal chunked message
				chunkedJSON, err := json.Marshal(chunkedMsg)
				if err != nil {
					return fmt.Errorf("failed to marshal chunked message: %w", err)
				}

				// Create rumor for chunk
				rumor := createRumor(string(chunkedJSON), senderPubkey, recipientPubkey.(string))

				// Create seal for chunk
				seal, err := createSeal(rumor, senderPrivkey.(string), recipientPubkey.(string))
				if err != nil {
					return fmt.Errorf("failed to create seal: %w", err)
				}

				// Create gift wrap for chunk
				event, err = createWrap(seal, recipientPubkey.(string))
				if err != nil {
					return fmt.Errorf("failed to create wrap: %w", err)
				}

				// Publish chunk
				err = relay.Publish(globalCtx, *event)
				if err != nil {
					log.Printf("Error publishing chunk %d: %v", i, err)
					return err
				}
			}
			return nil // Return after sending all chunks
		} else {
			// Decode sender's private key and recipient's public key
			_, senderPrivkey, err := nip19.Decode(globalLocalNostrKeys.LocalNostrPrivKey)
			if err != nil {
				return fmt.Errorf("invalid sender nsec: %w", err)
			}
			senderPubkey, err := nostr.GetPublicKey(senderPrivkey.(string))
			if err != nil {
				return fmt.Errorf("failed to derive sender pubkey: %w", err)
			}
			_, recipientPubkey, err := nip19.Decode(recipient)
			if err != nil {
				return fmt.Errorf("invalid recipient npub: %w", err)
			}

			// Create rumor
			rumor := createRumor(string(protoMessageJSON), senderPubkey, recipientPubkey.(string))

			// Create seal for recipient
			seal, err := createSeal(rumor, senderPrivkey.(string), recipientPubkey.(string))
			if err != nil {
				return fmt.Errorf("failed to create seal: %w", err)
			}

			// Create gift wrap for recipient
			event, err = createWrap(seal, recipientPubkey.(string))
			if err != nil {
				return fmt.Errorf("failed to create wrap: %w", err)
			}
		}

		if event == nil {
			return fmt.Errorf("failed to create event")
		}
		err = relay.Publish(globalCtx, *event)

		if err != nil {
			log.Printf("Error publishing event: %v", err)
			return err
		}
	}
	return nil
}

func nostrGetData(key string) (interface{}, bool) {
	return nostrMessageCache.Get(key)
}

func nostrSetData(key string, newMsg *ProtoMessage) {
	value, found := nostrGetData(key)
	var msgs []*ProtoMessage
	if found {
		msgs = value.([]*ProtoMessage)

	}

	msgs = append(msgs, newMsg)
	nostrMessageCache.Set(key, msgs, cache.DefaultExpiration)
}

func nostrClearSessionCache(sessionID string) {
	nostrMutex.Lock()
	defer nostrMutex.Unlock()

	// Clear messages for this session
	nostrMessageCache.Delete("message-" + sessionID)
	Logf("Cleared nostr message cache for session: %s", sessionID)
}

func nostrDownloadMessage(session, sessionKey, key string, tssServerImp ServiceImpl, endCh chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	isApplyingMessages := false
	msgMap := make(map[string]bool)

	// Create a mutex for protecting nostr message operations
	var nostrMsgMutex sync.Mutex

	for {
		select {
		case <-endCh:
			return
		default:
			if isApplyingMessages {
				continue
			}

			isApplyingMessages = true

			var err error

			var messages []struct {
				SessionID string   `json:"session_id,omitempty"`
				From      string   `json:"from,omitempty"`
				To        []string `json:"to,omitempty"`
				Body      string   `json:"body,omitempty"`
				SeqNo     string   `json:"sequence_no,omitempty"`
				Hash      string   `json:"hash,omitempty"`
			}
			nostrMsgMutex.Lock()
			msgs, found := nostrGetData("message-" + session)
			nostrMsgMutex.Unlock()

			if !found {
				isApplyingMessages = false
				continue
			}

			protoMessages, ok := msgs.([]*ProtoMessage)
			if !ok {
				Logln("BBMTLog", "Invalid message type for session:", session)
				isApplyingMessages = false
				continue
			}

			messages = make([]struct {
				SessionID string   `json:"session_id,omitempty"`
				From      string   `json:"from,omitempty"`
				To        []string `json:"to,omitempty"`
				Body      string   `json:"body,omitempty"`
				SeqNo     string   `json:"sequence_no,omitempty"`
				Hash      string   `json:"hash,omitempty"`
			}, 0, len(protoMessages))

			for _, protoMsg := range protoMessages {
				var message struct {
					SessionID string   `json:"session_id,omitempty"`
					From      string   `json:"from,omitempty"`
					To        []string `json:"to,omitempty"`
					Body      string   `json:"body,omitempty"`
					SeqNo     string   `json:"sequence_no,omitempty"`
					Hash      string   `json:"hash,omitempty"`
				}

				if err := json.Unmarshal(protoMsg.RawMessage, &message); err != nil {
					Logln("BBMTLog", "failed to parse RawMessage:", err)
					continue
				}

				messages = append(messages, message)
			}

			// Sort messages by sequence number
			sort.SliceStable(messages, func(i, j int) bool {
				seqNoI, errI := strconv.Atoi(messages[i].SeqNo)
				seqNoJ, errJ := strconv.Atoi(messages[j].SeqNo)

				if errI != nil || errJ != nil {
					Logln("BBMTLog", "Error converting SeqNo to int:", errI, errJ)
					return false
				}
				return seqNoI < seqNoJ
			})

			// Process messages sequentially
			for _, message := range messages {
				if message.From == key { //Skip messages from self
					continue
				}

				_, exists := msgMap[message.Hash]
				if exists {
					continue
				} else {
					msgMap[message.Hash] = true
				}

				status := getStatus(session)

				// Only process messages that match the expected seqNo

				status.Step++
				status.Index++
				status.Info = fmt.Sprintf("Received Message %s", message.SeqNo)
				setIndex(session, status.Info, status.Step, status.Index)

				// Decrypt message if necessary
				body := message.Body
				if len(sessionKey) > 0 {
					body, err = AesDecrypt(message.Body, sessionKey)
					if err != nil {
						Logln("BBMTLog", "failed to decrypt message:", err)
						continue
					}
				} else if len(decryptionKey) > 0 {
					body, err = EciesDecrypt(message.Body, decryptionKey)
					if err != nil {
						Logln("BBMTLog", "failed to decrypt ECIES message:", err)
						continue
					}
				}

				Logln("BBMTLog", "Applying message body:", body[:min(50, len(body))])
				if err := tssServerImp.ApplyData(body); err != nil {
					Logln("BBMTLog", "failed to apply message data:", err)
				}

				// Mark message as applied
				Logln("BBMTLog", "Message applied:", message.SeqNo)
				status.Step++
				status.Info = fmt.Sprintf("Applied Message %d", status.Index)
				setStep(session, status.Info, status.Step)

			}
			isApplyingMessages = false
		}
	}
}

func SendNostrPing(localParty, pingID, recipientNpub string) (bool, error) { //Used to see if the peer is connected to nostr relay.   PingID should be a random 32 byte string

	recipients := make([]string, 0, 1)
	for _, p := range globalLocalNostrKeys.NostrPartyPubKeys {
		if p == recipientNpub {
			recipients = append(recipients, p)
			break
		}
	}

	protoMessage := ProtoMessage{
		FunctionType:    "ping",
		From:            localParty,
		FromNostrPubKey: globalLocalNostrKeys.LocalNostrPubKey,
		Recipients:      recipients,
		RawMessage:      []byte(pingID),
	}

	err := nostrSend(protoMessage)
	if err != nil {
		return false, fmt.Errorf("error sending ping: %w", err)
	}
	nostrPingList = append(nostrPingList, protoMessage)
	Logf("ping sent to %s", recipients)

	for attempt := 0; attempt < 5; attempt++ {
		for i, ping := range nostrPingList {
			if string(ping.RawMessage) == pingID && ping.FunctionType == "pong" {
				Logf("pong received from %s for ping:%v", ping.Recipients[0], string(ping.RawMessage))
				Logf("%s is online", ping.Recipients[0])
				nostrPingList = append(nostrPingList[:i], nostrPingList[i+1:]...)
				return true, nil
			}
		}
		if attempt < 4 {
			time.Sleep(1 * time.Second)
		}
	}
	return false, nil
}

func returnNostrPong(localParty string, protoMessage ProtoMessage) {
	Logf("ping received from %s", protoMessage.From)
	var from = protoMessage.From
	protoMessage.FunctionType = "pong"
	protoMessage.Recipients = []string{protoMessage.FromNostrPubKey}
	protoMessage.From = localParty
	nostrSend(protoMessage)

	Logf("pong sent to %s", from)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func GetKeyShare(party string) (LocalState, error) {

	data, err := os.ReadFile(party + ".ks")
	if err != nil {
		fmt.Printf("Go Error GetKeyShare: %v", err)
	}

	// Decode base64
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		fmt.Printf("Go Error Decoding Base64: %v", err)
	}

	// Parse JSON into LocalState
	var keyShare LocalState
	if err := json.Unmarshal(decodedData, &keyShare); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v", err)
	}

	return keyShare, nil
}

// Simple function to stop NostrListen
func StopNostrListen() {
	Logf("Stopping NostrListen")
	if nostrListenCancel != nil {
		nostrListenCancel()
	}
}

func GetSession(sessionID string) (NostrSession, error) {
	for _, session := range nostrSessionList {
		if session.SessionID == sessionID {
			return session, nil
		}
	}
	return NostrSession{}, fmt.Errorf("session not found")
}

func GetSessions() ([]NostrSession, error) {
	return nostrSessionList, nil
}

func AddOrAppendNostrSession(protoMessage ProtoMessage) {
	newSession := true
	for i, existingSession := range nostrSessionList {
		if existingSession.SessionID == protoMessage.SessionID { //Session exists, update it
			existingSession.Status = protoMessage.FunctionType
			existingSession.Participants = protoMessage.Participants
			existingSession.TxRequest = protoMessage.TxRequest
			existingSession.Master = protoMessage.Master
			existingSession.SessionKey = protoMessage.SessionKey
			existingSession.ChainCode = protoMessage.ChainCode
			nostrSessionList[i] = existingSession
			newSession = false
			break
		}
	}

	if newSession {
		//Session doesn't exist, add it
		newSession := NostrSession{
			SessionID:    protoMessage.SessionID,
			Participants: protoMessage.Participants,
			TxRequest:    protoMessage.TxRequest,
			Master:       protoMessage.Master,
			SessionKey:   protoMessage.SessionKey,
			ChainCode:    protoMessage.ChainCode,
			Status:       protoMessage.FunctionType,
		}
		nostrSessionList = append(nostrSessionList, newSession)
	}
}

func NostrMpcTssSetup(relay, nsec1, npub1, npubs, sessionID, sessionKey, chaincode string) {

	npubsArray := strings.Split(npubs, ",")

	parties := strings.Join(npubsArray, ",")

	go NostrListen(npub1, nsec1, relay)
	time.Sleep(1 * time.Second)

	largestNpub := GetLexicographicallyFirstNpub(npubsArray)
	if largestNpub == npub1 {
		//I am master
		keyshare, err := JoinKeygen(npub1+".json", npub1, parties, "", "", sessionID, "", chaincode, sessionKey, "nostr")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		}
		fmt.Printf("Keyshare: %s\n", keyshare)
	} else {
		//I am not master
		fmt.Printf("I am not master\n")
		keyshare, err := JoinKeygen(npub1+".json", npub1, parties, "", "", sessionID, "", chaincode, sessionKey, "nostr")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		}
		fmt.Printf("Keyshare: %s\n", keyshare)
	}
}

// GetLexicographicallyFirstNpub takes a list of npubs and returns the one that comes first in lexicographical order
func GetLexicographicallyFirstNpub(npubs []string) string {
	if len(npubs) == 0 {
		return ""
	}

	// Sort the npubs in lexicographical order
	sort.Strings(npubs)

	// Return the first one (which will be lexicographically first)
	return npubs[0]
}
