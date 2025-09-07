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
	nostrSentEventsList       []SentEvent
	nostrPingList             []ProtoMessage
	nostrMessageCache         = cache.New(5*time.Minute, 10*time.Minute)
	relay                     *nostr.Relay
	globalCtx, _              = context.WithTimeout(context.Background(), 5*time.Minute) // 5 minute timeout for global operations
	KeysignApprovalTimeout    = 5 * time.Second                                          // Increased from 2 seconds for better handling of slow connections
	KeysignApprovalMaxRetries = 30
	nostrMutex                sync.Mutex
	chunkCache                = cache.New(5*time.Minute, 10*time.Minute)
	chunkMutex                sync.Mutex
	localState                LocalState
	localNostrKeys            NostrKeys
	globalLocalNostrKeys      NostrKeys
	globalLocalTesting        bool
	nostrListenCancel         context.CancelFunc
	// Timeout configurations for better handling of bad internet connections
	NostrConnectTimeout   = 60 * time.Second  // Extended timeout for relay connection
	NostrPublishTimeout   = 120 * time.Second // Extended timeout for publishing events
	NostrSubscribeTimeout = 60 * time.Second  // Extended timeout for subscription operations
	NostrRetryInterval    = 3 * time.Second   // Extended base retry interval
	NostrMaxBackoff       = 5 * time.Minute   // Extended maximum backoff for retries
	// Additional timeout configurations
	NostrHandshakeTimeout      = 60 * time.Second  // Extended timeout for handshake operations
	NostrMessageTimeout        = 90 * time.Second  // Extended timeout for message processing
	KeygenTimeout              = 320 * time.Second // Extended timeout for keygen operations
	globalVerbose         bool = false
)

type ProtoMessage struct {
	FunctionType        string              `json:"function_type"`
	MessageType         string              `json:"message_type"`
	Participants        []string            `json:"participants"`
	Recipients          []string            `json:"recipients"`
	FromNostrPubKey     string              `json:"from_nostr_pubkey"`
	PartyNpubs          []string            `json:"party_npubs"`
	SessionID           string              `json:"sessionID"`
	ChainCode           string              `json:"chain_code"`
	RawMessage          []byte              `json:"raw_message"`
	SeqNo               string              `json:"seq_no"`
	From                string              `json:"from"`
	To                  string              `json:"to"`
	TxRequest           TxRequest           `json:"tx_request"`
	Master              Master              `json:"master"`
	SessionKey          string              `json:"session_key"`
	ParticipantStatuses []ParticipantStatus `json:"participant_statuses"`
}

type ParticipantStatus struct {
	Participant string `json:"participant"`
	Status      string `json:"status"`
	Data        string `json:"data"`
}

type NostrSession struct {
	Status              string              `json:"status"`
	SessionID           string              `json:"session_id"`
	ChainCode           string              `json:"chain_code"`
	SessionKey          string              `json:"session_key"`
	Participants        []string            `json:"participants"`
	Master              Master              `json:"master"`
	TxRequest           TxRequest           `json:"tx_request"`
	ParticipantStatuses []ParticipantStatus `json:"participant_statuses"`
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

type SentEvent struct {
	EventID      string `json:"event_id"`
	SenderPubKey string `json:"sender_pubkey"`
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
	Master          Master `json:"master"`
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
		Logf("Go Error GetNostrKeys: %v", err)
	}

	var nostrKeys NostrKeys
	if err := json.Unmarshal(data, &nostrKeys); err != nil {
		Logf("Go Error Unmarshalling LocalState: %v", err)
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

	backoff := NostrRetryInterval

	for {
		// Check if we should stop
		select {
		case <-ctx.Done():
			log.Printf("NostrListen stopped by cancel")
			return
		default:
		}

		// Create a new context with extended timeout for this connection attempt
		ctxLoop, cancelLoop := context.WithTimeout(ctx, NostrConnectTimeout)

		// Connect to relay with extended timeout
		relay, err = nostr.RelayConnect(ctxLoop, nostrRelay)
		if err != nil {
			log.Printf("Connection failed: %v, retrying in %v...\n", err, backoff)
			cancelLoop()
			time.Sleep(backoff)
			// Exponential backoff with max of NostrMaxBackoff
			backoff = time.Duration(math.Min(float64(backoff*2), float64(NostrMaxBackoff)))
			continue
		}

		// Reset backoff on successful connection
		backoff = NostrRetryInterval

		since := nostr.Timestamp(time.Now().Add(-10 * time.Second).Unix())

		filters := []nostr.Filter{{
			Kinds: []int{1059}, // Subscribe to NIP-44 messages
			Tags:  map[string][]string{"p": {recipientPubkey}},
			Since: &since,
		}}

		// Create subscription context with extended timeout
		subCtx, subCancel := context.WithTimeout(ctx, NostrSubscribeTimeout)
		sub, err := relay.Subscribe(subCtx, filters)
		if err != nil {
			log.Printf("Subscription failed: %v, retrying in %v...\n", err, backoff)
			subCancel()
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
		subCancel()
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

	if protoMessage.FunctionType == "keysign" && protoMessage.MessageType != "message" {
		Logf("start_keysign received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.FunctionType == "keygen" && protoMessage.MessageType != "message" {
		Logf("start_keygen received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}
	if protoMessage.FunctionType == "keygen_successful" && protoMessage.MessageType != "message" {
		Logf("keygen_successful received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.FunctionType == "keygen_failed" && protoMessage.MessageType != "message" {
		Logf("keygen_failed received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
		AddOrAppendNostrSession(protoMessage)
	}

	if protoMessage.MessageType == "message" {
		//Logf("message received from %s to %s for SessionID:%v", protoMessage.From, localParty, protoMessage.SessionID)
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

func GenerateNostrSession() (string, string, string, error) {
	sessionId := randomSeed(64)
	sessionKey := randomSeed(64)
	chainCode := randomSeed(64)
	return sessionId, sessionKey, chainCode, nil
}

func NostrSpend(relay, localNpub, localNsec, partyNpubs, keyShare string, txRequest TxRequest, sessionID, sessionKey, verbose, newSession string) (string, error) {

	// all parties should already be listening

	//master is whoever first initiates the spend request
	globalVerbose, _ = strconv.ParseBool(verbose)
	globalLocalNostrKeys.NostrPartyPubKeys = strings.Split(partyNpubs, ",")
	globalLocalNostrKeys.LocalNostrPrivKey = localNsec
	globalLocalNostrKeys.LocalNostrPubKey = localNpub

	if newSession == "true" {
		txRequest.Master = Master{MasterPeer: localNpub, MasterPubKey: globalLocalNostrKeys.LocalNostrPubKey}
		initiateNostrHandshake(sessionID, "", sessionKey, localNpub, partyNpubs, "keysign", txRequest)
		time.Sleep(1 * time.Second)

		result, err := MpcSendBTC("", localNpub, partyNpubs, sessionID, sessionKey, "", "", keyShare, txRequest.DerivePath, txRequest.BtcPub, txRequest.SenderAddress, txRequest.ReceiverAddress, int64(txRequest.AmountSatoshi), int64(txRequest.FeeSatoshi), "nostr")
		if err != nil {
			Logf("Go Error: %v", err)
			return "", err
		} else {
			Logf("\n [%s] Keysign Result %s\n", localNpub, result)
			return result, nil
		}

	} else {

		protoMessage := ProtoMessage{
			SessionID:       sessionID,
			ChainCode:       "",
			SessionKey:      sessionKey,
			FunctionType:    "ack_handshake",
			From:            localNpub,
			FromNostrPubKey: localNpub,
			Recipients:      []string{txRequest.Master.MasterPubKey},
			Participants:    []string{localNpub},
			TxRequest:       txRequest,
			Master:          txRequest.Master,
		}

		AckNostrHandshake(protoMessage, localNpub)

		for i := 0; i < 60; i++ {
			for _, item := range nostrSessionList {
				if item.SessionID == sessionID {
					if item.Status == "keysign" {
						result, err := MpcSendBTC("", localNpub, partyNpubs, sessionID, sessionKey, "", "", keyShare, txRequest.DerivePath, txRequest.BtcPub, txRequest.SenderAddress, txRequest.ReceiverAddress, int64(txRequest.AmountSatoshi), int64(txRequest.FeeSatoshi), "nostr")
						if err != nil {
							Logf("Go Error: %v", err)
							return "", err
						} else {
							Logf("\n [%s] Keysign Result %s\n", localNpub, result)
							return result, nil
						}
					} else {
						Logf("%s is waiting for master to start session", localNpub)
					}
				}
				time.Sleep(1 * time.Second)
			}
		}
	}

	return "", nil

}

func GetAddressFromKeyShare(keyShare string) (string, error) {

	var localState LocalState
	if err := json.Unmarshal([]byte(keyShare), &localState); err != nil {
		fmt.Printf("Failed to parse keyshare: %v\n", err)
		return "", err
	}

	btcPub, err := GetDerivedPubKey(localState.PubKey, localState.ChainCodeHex, "m/44'/0'/0'/0/0", false)
	if err != nil {
		fmt.Printf("Failed to get derived public key: %v\n", err)
		return "", err
	}

	// Get the sender address
	senderAddress, err := ConvertPubKeyToBTCAddress(btcPub, "testnet3")
	if err != nil {
		fmt.Printf("Failed to get sender address: %v\n", err)
		return "", err
	}

	return senderAddress, nil
}

func NostrKeygen(relay, localNsec, localNpub, partyNpubs, chainCode, sessionKey, sessionID, verbose string) (string, error) {

	globalVerbose, _ = strconv.ParseBool(verbose)

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
		txRequest := TxRequest{} //Empty TxRequest because it's a keygen, not a keysign

		//Set the globalLocalNostrKeys
		globalLocalNostrKeys.NostrPartyPubKeys = strings.Split(partyNpubs, ",")
		globalLocalNostrKeys.LocalNostrPrivKey = localNsec
		globalLocalNostrKeys.LocalNostrPubKey = localNpub

		initiateNostrHandshake(sessionID, chainCode, sessionKey, localNpub, partyNpubs, "keygen", txRequest)
		Logf("Starting Master Keygen for session: %s", sessionID)

		ppmFile := localNpub + ".json"

		result, err := JoinKeygen(ppmFile, localNpub, partyNpubs, "", "", sessionID, "", chainCode, sessionKey, "nostr")
		if err != nil {
			Logf("Go Error: %v", err)
			err = publishNostrKeygenStatus(sessionID, localNpub, "", "keygen_failed") //Tell all parties keygen failed
			if err != nil {
				fmt.Printf("Failed to publish keygen_failed status: %v\n", err)
				return "", err
			}
			nostrListenCancel()
			return "", err

		} else {
			Logf("\n [%s] Keygen Result %s\n", localNpub, result)

			IsKeygenSuccess, err := VerifyKeygenSuccess(sessionID, result, localNpub)
			if err != nil {
				Logf("Failed to test keygen: %v", err)
				nostrListenCancel()
				nostrDeleteSession(sessionID)
				return "", err
			}

			if IsKeygenSuccess {
				nostrDeleteSession(sessionID)
				nostrListenCancel()
				return result, nil
			} else {
				nostrDeleteSession(sessionID)
				nostrListenCancel()
				return "", fmt.Errorf("keygen test failed, either one of the participants didn't respond with success or the bitcoin address generated from keyshare didn't match")
			}
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
				Logf("Go Error: %v", err)
				err = publishNostrKeygenStatus(sessions[0].SessionID, localNpub, "", "keygen_failed") //Tell all parties keygen failed
				if err != nil {
					fmt.Printf("Failed to publish keygen_failed status: %v\n", err)
					return "", err
				}
				nostrDeleteSession(sessions[0].SessionID)
				nostrListenCancel()
				return "", err
			} else {
				Logf("\n [%s] Keygen Result %s\n", localNpub, result)

				IsKeygenSuccess, err := VerifyKeygenSuccess(sessions[0].SessionID, result, localNpub)
				if err != nil {
					Logf("Failed to test keygen: %v", err)
					nostrListenCancel()
					return "", err
				}

				if IsKeygenSuccess {
					nostrListenCancel()
					nostrDeleteSession(sessions[0].SessionID)
					return result, nil
				} else {
					nostrListenCancel()
					nostrDeleteSession(sessions[0].SessionID)
					return "", fmt.Errorf("keygen test failed, either one of the participants didn't respond with success or the bitcoin address generated from keyshare didn't match")
				}

			}
		}
	}
}

func VerifyKeygenSuccess(sessionID, keyShare, localNpub string) (bool, error) {

	//Test by getting address from keyshare
	Logf("Verifying keygen success for %s", localNpub)

	address, err := GetAddressFromKeyShare(keyShare)
	if err != nil {
		fmt.Printf("Failed to get address from keyshare: %v\n", err)
		return false, err
	}

	//Tell all parties keygen successful by sending btc address
	err = publishNostrKeygenStatus(sessionID, localNpub, address, "keygen_successful")
	if err != nil {
		fmt.Printf("Failed to publish keygen_successful status: %v\n", err)
		return false, err
	}
	Logf("Published keygen_successful status for %s", localNpub)

	//Run test
	test, err := TestKeyGen(sessionID, keyShare, address)
	if err != nil {
		fmt.Printf("Failed to test keygen: %v\n", err)
		return false, err
	}

	return test, nil
}

func publishNostrKeygenStatus(sessionID, localNpub, BTCAddress, status string) error {

	for i := 0; i < len(nostrSessionList); i++ {
		if nostrSessionList[i].SessionID == sessionID {
			participantStatus := ParticipantStatus{
				Participant: localNpub,
				Status:      status,
				Data:        BTCAddress,
			}

			nostrSessionList[i].ParticipantStatuses = append(nostrSessionList[i].ParticipantStatuses, participantStatus)

			protoMessage := ProtoMessage{
				SessionID:           sessionID,
				FunctionType:        status,
				From:                localNpub,
				FromNostrPubKey:     localNpub,
				Recipients:          nostrSessionList[i].Participants,
				Participants:        nostrSessionList[i].Participants,
				ParticipantStatuses: nostrSessionList[i].ParticipantStatuses,
			}

			err := nostrSend(protoMessage, true)
			if err != nil {
				return fmt.Errorf("failed to send nostr message: %w", err)
			}
		}
	}

	return nil
}

func TestKeyGen(sessionID, keyShare, address string) (bool, error) {

	Logf("Waiting %d seconds for parties test keygen and respond if success or failed", int(KeygenTimeout.Seconds()))

	//if all participants respond with keygen_success and bitcoin addresses matches, return true
	var numOfParticipants bool = false
	var allAddressesMatch bool = false
	var allStatusesSuccessful bool = false

	for i := 0; i < int(KeygenTimeout.Seconds()); i++ {

		session, err := GetSession(sessionID)
		if err != nil {
			fmt.Printf("Failed to get session: %v\n", err)
			return false, err
		}

		if len(session.Participants) == len(session.ParticipantStatuses) {
			numOfParticipants = true
		} else {
			numOfParticipants = false
			Logf("Failed to get num of participants. Only have %d out of %d participants", len(session.ParticipantStatuses), len(session.Participants))
			Logf("Trying %d more times", int(KeygenTimeout.Seconds())-i)
		}

		allAddressesMatch = true
		for _, participantStatus := range session.ParticipantStatuses {
			if participantStatus.Data != address {
				allAddressesMatch = false
				Logf("Failed to get all addresses match")
				Logf("Trying %d more times", int(KeygenTimeout.Seconds())-i)
				continue
			}
		}

		allStatusesSuccessful = true
		for _, participantStatus := range session.ParticipantStatuses {
			if participantStatus.Status != "keygen_successful" {
				allStatusesSuccessful = false
				Logf("Failed to get all statuses successful")
				Logf("Trying %d more times", int(KeygenTimeout.Seconds())-i)
				continue
			}
		}

		if allStatusesSuccessful && allAddressesMatch && numOfParticipants {
			Logf("All NOSTR Keygen Tests Passed!")
			return true, nil
		}
		time.Sleep(1 * time.Second)
	}

	if !allAddressesMatch {
		return false, fmt.Errorf("Participants reported different BTC addresses!")
	}
	if !numOfParticipants {
		return false, fmt.Errorf("Not all participants reported their status!")
	}
	if !allStatusesSuccessful {
		return false, fmt.Errorf("Not all participants reported keygen_successful!")
	}
	return false, nil
}

// WaitForSessions polls GetSessions() every second for up to 5 minutes until it returns a non-empty result
func WaitForSessions() ([]NostrSession, error) {
	for i := 0; i < 300; i++ { // 5 minutes = 300 seconds (increased from 2 minutes)
		sessions, err := GetSessions()
		if err != nil {
			return nil, err
		}
		if len(sessions) > 0 {
			return sessions, nil
		}
		time.Sleep(1 * time.Second)
		Logf("Waiting for sessions... (attempt %d/300)", i+1)
	}
	return nil, fmt.Errorf("timeout waiting for sessions after 5 minutes")
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
	nostrSend(protoMessage, true)
	//==============================COLLECT ACK_HANDSHAKES==============================
	//time.Sleep(5 * time.Second)
	partyCount := len(globalLocalNostrKeys.NostrPartyPubKeys)
	retryCount := 0
	maxRetries := KeysignApprovalMaxRetries
	sessionReady := false
	for retryCount <= maxRetries {
		for _, item := range nostrSessionList {
			if item.SessionID == SessionID {
				time.Sleep(3 * time.Second)

				if functionType == "keygen" {
					participantCount := len(item.Participants)

					if participantCount == partyCount {
						Logf("All participants have approved, sending %s for session: %s", functionType, SessionID)
						sessionReady = true
						startSessionMaster(SessionID, item.Participants, localParty, functionType)
						break
					}
				} else {
					participantCount := len(item.Participants)
					participationRatio := float64(participantCount) / float64(partyCount)
					//time.Sleep(3 * time.Second)
					if participationRatio >= 0.66 && item.Status == "pending" {
						Logf("Enough participants have approved, sending %s for session: %s", functionType, SessionID)
						if item.Status == "pending" {
							sessionReady = true
							startSessionMaster(SessionID, item.Participants, localParty, functionType)
							break
						} else {
							return false, fmt.Errorf("session not ready")
						}

					} else {
						if retryCount >= maxRetries {

							participationRatio := float64(participantCount) / float64(partyCount)
							//time.Sleep(3 * time.Second)
							if participationRatio >= 0.66 && item.Status == "pending" {

								Logf("We have 2/3 of participants approved, sending %s for session: %s", functionType, SessionID)
								sessionReady = true
								startSessionMaster(SessionID, item.Participants, localParty, functionType)
								break

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
		if item.SessionID == sessionID && item.TxRequest == protoMessage.TxRequest && item.Status == "pending" { //This pending status check prevents a late party from interupting the current session if keysign is already in progress
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
	Logf("sending (ack_handshake) message to %s\n", protoMessage.Master.MasterPeer)

	nostrSession := NostrSession{
		SessionID:    protoMessage.SessionID,
		Participants: protoMessage.Participants,
		TxRequest:    protoMessage.TxRequest,
		Master:       protoMessage.Master,
		Status:       protoMessage.FunctionType,
		SessionKey:   protoMessage.SessionKey,
		ChainCode:    protoMessage.ChainCode,
	}

	if !contains(nostrSession.Participants, nostrSession.Master.MasterPeer) {
		nostrSession.Participants = append(nostrSession.Participants, nostrSession.Master.MasterPeer)
		for i, item := range nostrSessionList {
			if item.SessionID == nostrSession.SessionID {
				nostrSessionList[i] = nostrSession
			}
		}
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
		FromNostrPubKey: localParty,
		Recipients:      []string{nostrSession.Master.MasterPeer},
		Participants:    nostrSession.Participants,
		TxRequest:       nostrSession.TxRequest,
		Master:          nostrSession.Master,
	}

	nostrSend(ackProtoMessage, true)

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
			nostrSend(startKeysignProtoMessage, true)
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
	publishDeleteEvent() //TODO: This needs to ask the relay to delete all events
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

func nostrSend(protoMessage ProtoMessage, deleteEvent bool) error {

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

				// Publish chunk with timeout and retry logic
				if err := publishWithRetry(event); err != nil {
					log.Printf("Error publishing chunk %d: %v", i, err)
					return err
				}

				if deleteEvent {
					nostrSentEventsList = append(nostrSentEventsList, SentEvent{EventID: event.ID, SenderPubKey: senderPubkey})
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

			if deleteEvent {
				nostrSentEventsList = append(nostrSentEventsList, SentEvent{EventID: event.ID, SenderPubKey: senderPubkey})
			}
		}

		if event == nil {
			return fmt.Errorf("failed to create event")
		}

		// Publish event with timeout and retry logic
		if err := publishWithRetry(event); err != nil {
			log.Printf("Error publishing event: %v", err)
			return err
		}

	}
	return nil
}

func publishDeleteEvent() error {

	// Logf("Publishing delete event")
	// protoMessageJSON, err := json.Marshal(protoMessage)
	// if err != nil {
	// 	log.Printf("Error marshalling protoMessage: %v", err)
	// 	return err
	// }

	// protoMessageSize := int64(len(protoMessageJSON))
	// var event *nostr.Event

	// _, senderPrivkey, err := nip19.Decode(globalLocalNostrKeys.LocalNostrPrivKey)
	// if err != nil {
	// 	return fmt.Errorf("invalid sender nsec: %w", err)
	// }
	// senderPubkey, err := nostr.GetPublicKey(senderPrivkey.(string))
	// Logf("Sender Pubkey: %s", senderPubkey)

	// if err != nil {
	// 	return fmt.Errorf("failed to derive sender pubkey: %w", err)
	// }
	// _, recipientPubkey, err := nip19.Decode(recipient)
	// if err != nil {
	// 	return fmt.Errorf("invalid recipient npub: %w", err)
	// }

	// // Create rumor
	// rumor := createRumor(string(protoMessageJSON), senderPubkey, recipientPubkey.(string))

	// // Create seal for recipient
	// seal, err := createSeal(rumor, senderPrivkey.(string), recipientPubkey.(string))
	// if err != nil {
	// 	return fmt.Errorf("failed to create seal: %w", err)
	// }

	// // Create gift wrap for recipient
	// event, err = createWrap(seal, recipientPubkey.(string))
	// if err != nil {
	// 	return fmt.Errorf("failed to create wrap: %w", err)
	// }

	// // Publish event with timeout and retry logic
	// if err := publishWithRetry(event); err != nil {
	// 	log.Printf("Error publishing event: %v", err)
	// 	return err
	// }

	// Create a new event
	// 	event := nostr.Event{
	// 		Kind:      4, // NIP-04 encrypted DM
	// 		CreatedAt: nostr.Now(),
	// 		Tags:      nostr.Tags{{"p", "npub1qpv7dy8p9l9q2dmu3gem6td58z8hx0maxhjf2tpajpakepcslszsxuj4kz"}},
	// 	}

	// 	// Encrypt the message
	// 	encrypted, err := nip04.Encrypt("things", []byte(globalLocalNostrKeys.LocalNostrPrivKey))
	// 	if err != nil {
	// 		fmt.Printf("Encryption failed: %v\n", err)
	// 		return err
	// 	}
	// 	event.Content = encrypted

	// 	// Sign the event
	// 	err = event.Sign(globalLocalNostrKeys.LocalNostrPrivKey)
	// 	if err != nil {
	// 		fmt.Printf("Signing failed: %v\n", err)
	// 		return err
	// 	}

	// 	deleteEvent := &nostr.Event{
	// 		Kind:      5, // NIP-09 delete event kind
	// 		CreatedAt: nostr.Now(),
	// 		Content:   "Event deleted", // Optional content explaining why it was deleted
	// 		Tags:      nostr.Tags{
	// 			//{"e", eventID}, // Tag the event ID to be deleted
	// 		},
	// 	}

	// 	err = relay.Publish(context.Background(), event)
	// 	if err != nil {
	// 		fmt.Printf("Failed to publish: %v\n", err)
	// 		return err
	// 	}

	// 	for _, item := range nostrSentEventsList {
	// 		deleteEvent.Tags = append(deleteEvent.Tags, nostr.Tag{"e", item.EventID})
	// 		//deleteEvent.PubKey = item.SenderPubKey
	// 	}

	// 	Logf("deleteEvent: %v", deleteEvent)
	// 	// Sign the event with the private key
	// 	_, senderPrivkey, err := nip19.Decode(globalLocalNostrKeys.LocalNostrPrivKey)
	// 	if err != nil {
	// 		return fmt.Errorf("invalid sender nsec: %w", err)
	// 	}
	// 	if err := deleteEvent.Sign(senderPrivkey.(string)); err != nil {
	// 		Logf("Signing failed with error: %v", err)
	// 		return fmt.Errorf("failed to sign delete event: %w", err)
	// 	}

	// 	// Publish the delete event using the existing retry mechanism
	// 	if err := publishWithRetry(deleteEvent); err != nil {
	// 		return fmt.Errorf("failed to publish delete event: %w", err)
	// 	}
	// 	Logf("Published deletion request for all events")
	// 	return nil

	// }
	return nil
}

// publishWithRetry publishes an event with timeout and retry logic
func publishWithRetry(event *nostr.Event) error {
	maxRetries := 3
	backoff := 1 * time.Second

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Create context with timeout for publishing
		ctx, cancel := createTimeoutContext(NostrPublishTimeout)

		err := relay.Publish(ctx, *event)
		cancel()

		if err == nil {
			return nil // Success
		}

		log.Printf("Publish attempt %d failed for %d: %v", attempt+1, event.Kind, err)

		if attempt < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2 // Exponential backoff
		}
	}

	return fmt.Errorf("failed to publish %d after %d attempts", event.Kind, maxRetries)
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

	err := nostrSend(protoMessage, true)
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
	nostrSend(protoMessage, true)

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
		Logf("Go Error GetKeyShare: %v", err)
	}

	// Decode base64
	decodedData, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		Logf("Go Error Decoding Base64: %v", err)
	}

	// Parse JSON into LocalState
	var keyShare LocalState
	if err := json.Unmarshal(decodedData, &keyShare); err != nil {
		Logf("Go Error Unmarshalling LocalState: %v", err)
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
			// Append only non-duplicate participant statuses
			for _, newStatus := range protoMessage.ParticipantStatuses {
				exists := false
				for _, existingStatus := range existingSession.ParticipantStatuses {
					if existingStatus.Participant == newStatus.Participant {
						exists = true
						break
					}
				}
				if !exists {
					existingSession.ParticipantStatuses = append(existingSession.ParticipantStatuses, newStatus)
				}
			}

			nostrSessionList[i] = existingSession
			newSession = false
			break
		}
	}

	if newSession {
		//Session doesn't exist, add it
		newSession := NostrSession{
			SessionID:           protoMessage.SessionID,
			Participants:        protoMessage.Recipients,
			TxRequest:           protoMessage.TxRequest,
			Master:              protoMessage.Master,
			SessionKey:          protoMessage.SessionKey,
			ChainCode:           protoMessage.ChainCode,
			Status:              protoMessage.FunctionType,
			ParticipantStatuses: protoMessage.ParticipantStatuses,
		}
		nostrSessionList = append(nostrSessionList, newSession)
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

// createTimeoutContext creates a new context with the specified timeout
func createTimeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}
