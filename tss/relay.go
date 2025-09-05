package tss

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/patrickmn/go-cache"
)

// Global Cache
var dataCache = cache.New(5*time.Minute, 10*time.Minute)

// Mutex for safe concurrent operations
var mutex sync.Mutex

// Session structure
type Session struct {
	SessionID    string   `json:"sessionID"`
	Participants []string `json:"participants"`
}

// Message structure
type Message struct {
	SessionID string   `json:"session_id,omitempty"`
	From      string   `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	Body      string   `json:"body,omitempty"`
	SeqNo     string   `json:"sequence_no,omitempty"`
	Hash      string   `json:"hash,omitempty"`
}

// normalizeParticipant trims whitespace and can be extended later for case rules
func normalizeParticipant(p string) string {
	return strings.TrimSpace(p)
}

// uniqueNormalizedParticipants returns a de-duplicated, order-preserving list
func uniqueNormalizedParticipants(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		n := normalizeParticipant(p)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	return out
}

// ---- Helper Functions ----
func getSessionID(r *http.Request) string {
	vars := mux.Vars(r)
	return vars["sessionID"]
}

func getKeyParam(r *http.Request) string {
	vars := mux.Vars(r)
	return vars["participantKey"]
}

func getHashParam(r *http.Request) string {
	vars := mux.Vars(r)
	return vars["hash"]
}

// ---- Session Handlers ----
func postSession(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	if sessionID == "" {
		http.Error(w, "sessionID is required", http.StatusBadRequest)
		return
	}

	var participants []string
	if err := json.NewDecoder(r.Body).Decode(&participants); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	// Normalize and de-duplicate incoming participants
	participants = uniqueNormalizedParticipants(participants)
	if len(participants) == 0 {
		http.Error(w, "no participants provided", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	key := "session-" + sessionID
	if session, found := getData(key); found {
		existingSession := session.(Session)
		// Merge and de-duplicate
		merged := uniqueNormalizedParticipants(append(existingSession.Participants, participants...))
		existingSession.Participants = merged
		setData(key, existingSession)
		w.WriteHeader(http.StatusOK)
		Logln("BBMTLog", "Session %s updated; participants=%v", sessionID, merged)
		return
	}

	// New session
	setData(key, Session{SessionID: sessionID, Participants: participants})
	w.WriteHeader(http.StatusCreated)
	Logln("BBMTLog", "Session %s created; participants=%v", sessionID, participants)
}

func getSession(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	key := "session-" + sessionID

	if session, found := getData(key); found {
		w.Header().Set("Content-Type", "application/json")
		p := uniqueNormalizedParticipants(session.(Session).Participants)
		json.NewEncoder(w).Encode(p)
		return
	}

	http.Error(w, "session not found", http.StatusNotFound)
}

func deleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	key := "session-" + sessionID

	mutex.Lock()
	defer mutex.Unlock()

	dataCache.Delete(key)
	dataCache.Delete(key + "-start")
	w.WriteHeader(http.StatusOK)
	Logln("BBMTLog", fmt.Sprintf("Session %s deleted", sessionID))
}

func completedKeysign(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	// Read 'message' header and 'body' from the request body
	messageID := r.Header.Get("message_id")
	if messageID == "" {
		http.Error(w, "message_id header is required", http.StatusBadRequest)
		return
	}

	// Read the request body to get the body data
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// Example operation to mark local party keysign complete (you can change it to suit your logic)
	keysignCompleteKey := "keysign-complete-" + sessionID
	setData(keysignCompleteKey, map[string]interface{}{
		"sessionID": sessionID,
		"messageID": messageID,
		"body":      string(bodyBytes),
	})

	// Respond to client
	w.WriteHeader(http.StatusOK)
	Logln("BBMTLog", fmt.Sprintf("completedKeysign succeeded: Session %s, MessageID %s", sessionID, messageID))
}

func completedKeygen(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)

	// Read request body (local party ID)
	var localPartyID []string
	if err := json.NewDecoder(r.Body).Decode(&localPartyID); err != nil || len(localPartyID) == 0 {
		http.Error(w, "invalid or missing localPartyID", http.StatusBadRequest)
		return
	}

	// Save the completed local party ID to session data (this can be an operation to mark a local party's completion)
	partyCompletionKey := "local-party-complete-" + sessionID
	setData(partyCompletionKey, localPartyID)

	// Respond to client
	w.WriteHeader(http.StatusCreated)
	Logln("BBMTLog", fmt.Sprintf("completedKeygen succeeded: Session %s, LocalPartyID %s", sessionID, localPartyID[0]))
}

// ---- Message Handlers ----
func postMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	key := "message-" + sessionID

	var msg Message
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "invalid JSON payload", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	var messages []Message
	if data, found := getData(key); found {
		messages = data.([]Message)
	}
	messages = append(messages, msg)
	setData(key, messages)

	w.WriteHeader(http.StatusOK)
	Logln("BBMTLog", fmt.Sprintf("Message added to session %s: %+v", sessionID, msg.Hash))
}

func getMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	participantKey := getKeyParam(r)
	key := "message-" + sessionID

	if data, found := getData(key); found {
		messages := data.([]Message)
		filtered := []Message{}
		for _, msg := range messages {
			for _, to := range msg.To {
				if to == participantKey {
					filtered = append(filtered, msg)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(filtered)
		return
	}

	http.Error(w, "no messages found", http.StatusNotFound)
}

func deleteTssMessage(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r)
	participantKey := getKeyParam(r)
	hash := getHashParam(r)
	key := "message-" + sessionID

	Logln("BBMTLog", "deleteTssMessage called: session=%s, participant=%s, hash=%s", sessionID, participantKey, hash)

	mutex.Lock()
	defer mutex.Unlock()

	if data, found := getData(key); found {
		messages := data.([]Message)
		Logln("BBMTLog", fmt.Sprintf("Found %d messages in session %s", len(messages), sessionID))

		// Debug: Show all messages to understand the data structure
		Logln("BBMTLog", "All messages in session:")
		for i, msg := range messages {
			Logln("BBMTLog", fmt.Sprintf("  Message[%d]: Hash='%s', From='%s', To='%v', SeqNo='%s'", i, msg.Hash, msg.From, msg.To, msg.SeqNo))
		}

		filtered := []Message{}
		deletedCount := 0
		for _, msg := range messages {
			// Check if this message should be deleted:
			// 1. Hash matches AND
			// 2. Participant is either the sender OR the recipient
			shouldDelete := false
			if msg.Hash == hash {
				if msg.From == participantKey {
					shouldDelete = true
					Logln("BBMTLog", fmt.Sprintf("Deleting message sent by %s with hash %s", participantKey, hash))
				} else {
					// Check if participant is in the recipients list
					for _, recipient := range msg.To {
						if recipient == participantKey {
							shouldDelete = true
							Logln("BBMTLog", fmt.Sprintf("Deleting message received by %s with hash %s", participantKey, hash))
							break
						}
					}
				}
			}

			if !shouldDelete {
				filtered = append(filtered, msg)
			} else {
				deletedCount++
				Logln("BBMTLog", fmt.Sprintf("Message deleted from session %s by %s with hash %s", sessionID, participantKey, hash))
			}
		}

		Logln("BBMTLog", fmt.Sprintf("Deleted %d message(s), remaining: %d", deletedCount, len(filtered)))
		setData(key, filtered)
		w.WriteHeader(http.StatusOK)
		return
	}

	Logln("BBMTLog", fmt.Sprintf("No messages found for session %s", sessionID))
	http.Error(w, "message not found", http.StatusNotFound)
}

// ---- Utility Functions ----
func setData(key string, value interface{}) {
	dataCache.Set(key, value, cache.DefaultExpiration)
}

func getData(key string) (interface{}, bool) {
	return dataCache.Get(key)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // allow any origin
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==============================
// 🚀 Server Initialization
// ==============================
func listen(port string) *http.Server {
	r := mux.NewRouter()

	// Session Routes
	r.HandleFunc("/{sessionID}", postSession).Methods("POST")
	r.HandleFunc("/{sessionID}", getSession).Methods("GET")
	r.HandleFunc("/{sessionID}", deleteSession).Methods("DELETE")

	// Handlers for session completions
	r.HandleFunc("/complete/keysign/{sessionID}", completedKeysign).Methods("POST")
	r.HandleFunc("/complete/keygen/{sessionID}", completedKeygen).Methods("POST")

	// Message Routes
	r.HandleFunc("/message/{sessionID}", postMessage).Methods("POST")
	r.HandleFunc("/message/{sessionID}/{participantKey}", getMessage).Methods("GET")
	r.HandleFunc("/message/{sessionID}/{participantKey}/{hash}", deleteTssMessage).Methods("DELETE")

	handler := corsMiddleware(r)

	server := &http.Server{
		Addr:    "0.0.0.0:" + port,
		Handler: handler,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			Logln("BBMTLog", fmt.Sprintf("Server failed: %v", err))
		}
	}()

	return server
}

var server *http.Server = nil

func RunRelay(port string) (string, error) {
	if server != nil {
		StopRelay()
	}
	time.Sleep(time.Second)
	go func() {
		server = listen(port)
	}()
	Logln("BBMTLog", fmt.Sprintf("Relay started on port %s", port))
	return "ok", nil
}

func StopRelay() (string, error) {
	if server == nil {
		return "already_closed", nil
	}
	server.Close()
	server = nil
	return "ok", nil
}
