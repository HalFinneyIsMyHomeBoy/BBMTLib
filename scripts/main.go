package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BoldBitcoinWallet/BBMTLib/tss"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

var nostrRelay string

func randomSeed(length int) string {
	const characters = "0123456789abcdef"
	result := make([]byte, length)
	rand.Read(result)
	for i := 0; i < length; i++ {
		result[i] = characters[int(result[i])%len(characters)]
	}
	return string(result)
}

func main() {

	nostrRelay = "ws://bbw-nostr.xyz"

	mode := os.Args[1]

	if mode == "keypair" {
		kp, _ := tss.GenerateKeyPair()
		fmt.Println(kp)
	}

	if mode == "generateNostrKeys" {
		fmt.Println("Starting Nostr peer generation...")
		// Generate 3 keypairs
		numPeers, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("Error parsing number of peers: %v\n", err)
			return
		}
		peerKeys := make(map[string]map[string]string)
		allPubKeys := make(map[string]string)

		// Generate keys for 3 peers
		for i := 1; i <= numPeers; i++ {
			peerName := fmt.Sprintf("peer%d", i)
			fmt.Printf("Generating keys for %s...\n", peerName)

			// Generate keypair
			privateKey := nostr.GeneratePrivateKey()
			publicKey, err := nostr.GetPublicKey(privateKey)
			if err != nil {
				fmt.Printf("Error generating public key for %s: %v\n", peerName, err)
				return
			}

			// Encode to nsec and npub format
			nsec, err := nip19.EncodePrivateKey(privateKey)
			if err != nil {
				fmt.Printf("Error encoding private key for %s: %v\n", peerName, err)
				return
			}

			npub, err := nip19.EncodePublicKey(publicKey)
			if err != nil {
				fmt.Printf("Error encoding public key for %s: %v\n", peerName, err)
				return
			}

			peerKeys[peerName] = map[string]string{
				"nsec": nsec,
				"npub": npub,
			}
			allPubKeys[peerName] = npub
			fmt.Printf("Successfully generated keys for %s\n", peerName)
		}

		// Create individual .nostr files for each peer
		// Ensure the scripts/ directory exists
		fmt.Println("\nCreating .nostr files...")
		for i := 1; i <= numPeers; i++ {
			peerName := fmt.Sprintf("peer%d", i)
			fmt.Printf("Creating file for %s...\n", peerName)

			nostrConfig := struct {
				LocalNostrPubKey  string            `json:"local_nostr_pub_key"`
				LocalNostrPrivKey string            `json:"local_nostr_priv_key"`
				NostrPartyPubKeys map[string]string `json:"nostr_party_pub_keys"`
			}{
				LocalNostrPubKey:  peerKeys[peerName]["npub"],
				LocalNostrPrivKey: peerKeys[peerName]["nsec"],
				NostrPartyPubKeys: allPubKeys,
			}

			// Convert to JSON with indentation
			jsonData, err := json.MarshalIndent(nostrConfig, "", "  ")
			if err != nil {
				fmt.Printf("Error creating JSON for %s: %v\n", peerName, err)
				continue
			}

			// Write to file
			filename := fmt.Sprintf("%s.nostr", peerName)
			err = os.WriteFile(filename, jsonData, 0644)
			if err != nil {
				fmt.Printf("Error writing file for %s: %v\n", peerName, err)
				continue
			}

			// Verify file was created
			if _, err := os.Stat(filename); err == nil {
				fmt.Printf("Successfully created %s\n", filename)
			} else {
				fmt.Printf("Warning: Could not verify creation of %s: %v\n", filename, err)
			}
		}
		fmt.Println("\nNostr peer generation completed!")
	}

	if mode == "nostrKeypair" {
		// Generate a new private key
		privateKey := nostr.GeneratePrivateKey()

		// Get the public key from the private key
		publicKey, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			fmt.Printf("Error generating public key: %v\n", err)
			return
		}

		// Encode to nsec and npub format
		nsec, err := nip19.EncodePrivateKey(privateKey)
		if err != nil {
			fmt.Printf("Error encoding private key: %v\n", err)
			return
		}

		npub, err := nip19.EncodePublicKey(publicKey)
		if err != nil {
			fmt.Printf("Error encoding public key: %v\n", err)
			return
		}
		keyPair := map[string]string{
			"privateKey": nsec,
			"publicKey":  npub,
		}
		keyPairJSON, _ := json.Marshal(keyPair)
		fmt.Println(string(keyPairJSON))
	}

	if mode == "random" {
		fmt.Println(randomSeed(64))
	}

	if mode == "getAddress" {
		if len(os.Args) != 6 {
			fmt.Println("Usage: go run main.go getAddress <pubKey> <chainCode> <path> <network>")
			os.Exit(1)
		}
		pubKey := os.Args[2]
		chainCode := os.Args[3]
		path := os.Args[4]
		network := os.Args[5]
		// Get derived public key
		btcPub, err := tss.GetDerivedPubKey(pubKey, chainCode, path, false)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

		// Convert to testnet3 address
		btcP2Pkh, err := tss.ConvertPubKeyToBTCAddress(btcPub, network)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}

		fmt.Println(btcP2Pkh)
	}

	if mode == "relay" {
		port := os.Args[2]
		defer tss.StopRelay()
		tss.RunRelay(port)
		select {}
	}

	if mode == "debugNostrKeygen" {

		nostrRelay := "ws://bbw-nostr.xyz"
		localNpub := "npub1dez6tr8jl02ympvl5q5uhac6up92e9xy3tad6hazqgc8twslenvscyvq7q"
		localNsec := "nsec1q9jgu6wmqkswmpxduke6t60vwdaj73v79m0mvm8505y5gqm33ryq4h3k5d"
		//remote "nsec12p2mh25m5frvncwwmglrrjt3t2mrpctl4x6kpzkl6nr2g5gw806sjhefv6"
		partyNpubs := "npub1dez6tr8jl02ympvl5q5uhac6up92e9xy3tad6hazqgc8twslenvscyvq7q,npub19k20weeynfk3fs457qre42vplps83ey6eu3jf607j8tcs2lmnjhs7u7wad,npub1mtq2lla3tzuz4rs8asshp9cwrd2rcu92p0j6dssy7cwsawhdumgqsfy2cz"
		verbose := "true"

		result, err := tss.NostrKeygen(nostrRelay, localNsec, localNpub, partyNpubs, verbose)
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("Keygen Result: %s\n", result)
		}

		select {}
	}

	if mode == "nostrKeygen" {
		if len(os.Args) != 10 {
			fmt.Println("Usage: go run main.go nostrKeygen <relay> <localNsec> <localNpub> <partyNpubs> <sessionID> <sessionKey> <chainCode> <verbose>")
			os.Exit(1)
		}
		nostrRelay := os.Args[2]
		localNsec := os.Args[3]
		localNpub := os.Args[4]
		partyNpubs := os.Args[5] //all party npubs
		verbose := os.Args[6]

		result, err := tss.NostrKeygen(nostrRelay, localNsec, localNpub, partyNpubs, verbose)
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("Keygen Result: %s\n", result)

			// Save result to file with npub as filename and .ks extension
			filename := localNpub + ".ks"
			encodedResult := base64.StdEncoding.EncodeToString([]byte(result))
			if err := os.WriteFile(filename, []byte(encodedResult), 0644); err != nil {
				fmt.Printf("Failed to save keyshare to %s: %v\n", filename, err)
			} else {
				fmt.Printf("Keyshare saved to %s\n", filename)
			}
		}

		select {}

	}

	if mode == "keygen" {
		// prepare args
		server := os.Args[2]
		session := os.Args[3]
		chainCode := os.Args[4]
		party := os.Args[5]
		parties := os.Args[6]
		encKey := os.Args[7]
		decKey := os.Args[8]
		sessionKey := os.Args[9]
		net_type := os.Args[10]

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		ppmFile := party + ".json"
		keyshareFile := party + ".ks"

		//join keygen
		keyshare, err := tss.JoinKeygen(ppmFile, party, parties, encKey, decKey, session, server, chainCode, sessionKey, net_type)
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {

			// Create LocalState with Nostr keys

			var localState tss.LocalState

			if err := json.Unmarshal([]byte(keyshare), &localState); err != nil {
				fmt.Printf("Failed to parse keyshare for %s: %v\n", party, err)
			}

			// // Marshal the updated LocalState
			updatedKeyshare, err := json.Marshal(localState)
			fmt.Printf(party + " Keygen Result Saved\n")
			encodedResult := base64.StdEncoding.EncodeToString(updatedKeyshare)

			if err := os.WriteFile(keyshareFile, []byte(encodedResult), 0644); err != nil {
				fmt.Printf("Failed to save keyshare for %s: %v\n", party, err)
			}

			var kgR tss.KeygenResponse
			if err := json.Unmarshal([]byte(keyshare), &kgR); err != nil {
				fmt.Printf("Failed to parse keyshare for %s: %v\n", party, err)
			}

			// print out pubkeys and p2pkh address
			fmt.Printf(party+" Public Key: %s\n", kgR.PubKey)
			xPub := kgR.PubKey
			btcPath := "m/44'/0'/0'/0/0"
			btcPub, err := tss.GetDerivedPubKey(xPub, chainCode, btcPath, false)
			if err != nil {
				fmt.Printf("Failed to generate btc pubkey for %s: %v\n", party, err)
			} else {
				fmt.Printf(party+" BTC Public Key: %s\n", btcPub)
				btcP2Pkh, err := tss.ConvertPubKeyToBTCAddress(btcPub, "testnet3")
				if err != nil {
					fmt.Printf("Failed to generate btc address for %s: %v\n", party, err)
				} else {
					fmt.Printf(party+" address btcP2Pkh: %s\n", btcP2Pkh)
				}
			}
		}
	}

	if mode == "keysign" {

		// prepare args
		server := os.Args[2]
		session := os.Args[3]
		party := os.Args[4]
		parties := os.Args[5]
		encKey := os.Args[6]
		decKey := os.Args[7]
		keyshare := os.Args[8]
		derivePath := os.Args[9]
		message := os.Args[10]

		sessionKey := os.Args[11]
		net_type := os.Args[12]

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		// message hash, base64 encoded
		messageHash, _ := tss.Sha256(message)
		messageHashBytes := []byte(messageHash)
		messageHashBase64 := base64.StdEncoding.EncodeToString(messageHashBytes)

		keysign, err := tss.JoinKeysign(server, party, parties, session, sessionKey, encKey, decKey, keyshare, derivePath, messageHashBase64, net_type)
		time.Sleep(time.Second)

		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("\n [%s] Keysign Result %s\n", party, keysign)
		}
	}

	if mode == "debugNostrSpend" {

		nostrRelay := "ws://bbw-nostr.xyz"
		localNpub := "npub1cth3ap55m833fp57h6t7yfs32dq59ehqsm8dfvj6q74x5xumh6ksjlz7pz"
		localNsec := "nsec1354cvkfja502qhnkggxf40l33xum4sskfzdn4mmut2zm00mjp7mqkmhnpd"

		partyNpubs := "npub1cth3ap55m833fp57h6t7yfs32dq59ehqsm8dfvj6q74x5xumh6ksjlz7pz,npub1v7flccr3ak4p8ewmalrs0luddphsf0chane9pf36w53pa7rjcn9qhevzrq,npub1eqzf897u88chm9yy67geyxtlp38e6s2rvyw8ejcz0fa0rw5qjwhq4rmaet"
		derivePath := "m/44'/0'/0'/0/0"

		keyshareFile := localNpub + ".ks"
		keyshare, err := os.ReadFile(keyshareFile)
		if err != nil {
			fmt.Printf("Error reading keyshare file for %s: %v\n", localNpub, err)
			return
		}

		decodedKeyshare, err := base64.StdEncoding.DecodeString(string(keyshare))
		if err != nil {
			fmt.Printf("Failed to decode base64 keyshare: %v\n", err)
			return
		}

		// Get the public key and chain code from keyshare
		var localState tss.LocalState
		if err := json.Unmarshal(decodedKeyshare, &localState); err != nil {
			fmt.Printf("Failed to parse keyshare: %v\n", err)
			return
		}

		// Get the derived public key using chain code from keyshare
		btcPub, err := tss.GetDerivedPubKey(localState.PubKey, localState.ChainCodeHex, derivePath, false)
		if err != nil {
			fmt.Printf("Failed to get derived public key: %v\n", err)
			return
		}

		// Get the sender address
		senderAddress, err := tss.ConvertPubKeyToBTCAddress(btcPub, "testnet3")
		if err != nil {
			fmt.Printf("Failed to get sender address: %v\n", err)
			return
		}

		fmt.Printf("Successfully processed keyshare for %s\n", localNpub)

		// Create TxRequest struct
		txRequest := tss.TxRequest{
			SenderAddress:   senderAddress,
			ReceiverAddress: "mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV",
			AmountSatoshi:   1000,
			FeeSatoshi:      600,
			DerivePath:      "m/44'/0'/0'/0/0",
			BtcPub:          btcPub,
		}
		//verbose := "true"

		sessionID := randomSeed(64)
		sessionKey := randomSeed(64)

		result, err := tss.NostrSpend(nostrRelay, localNpub, localNsec, partyNpubs, string(keyshare), txRequest, sessionID, sessionKey, "true", "true")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("Keygen Result: %s\n", result)
		}

		select {}
	}

	if mode == "nostrSendBTC" {

		//This is to be called by the party initiating the session to send BTC
		//The party to initiate this is the master by default for the session.
		fmt.Println(len(os.Args))
		if len(os.Args) != 8 {
			fmt.Println("Usage: go run main.go nostrSendBTC <parties> <derivePath> <receiverAddress> <amountSatoshi> <estimatedFee> <peer> <net_type> <localTesting>")
			os.Exit(1)
		}
		parties := os.Args[2]
		derivePath := os.Args[3]
		receiverAddress := os.Args[4]
		amountSatoshi, err := strconv.ParseInt(os.Args[5], 10, 64)
		if err != nil {
			fmt.Printf("Invalid amountSatoshi: %v\n", err)
			return
		}
		estimatedFee, err := strconv.ParseInt(os.Args[6], 10, 64)
		if err != nil {
			fmt.Printf("Invalid estimatedFee: %v\n", err)
			return
		}
		peer := os.Args[7]

		fmt.Println("InitiateNostrSendBTC called")

		// Read and decode keyshare file for this peer
		keyshareFile := peer + ".ks"
		keyshare, err := os.ReadFile(keyshareFile)
		if err != nil {
			fmt.Printf("Error reading keyshare file for %s: %v\n", peer, err)
			return
		}
		decodedKeyshare, err := base64.StdEncoding.DecodeString(string(keyshare))
		if err != nil {
			fmt.Printf("Failed to decode base64 keyshare: %v\n", err)
			return
		}

		// Get the public key and chain code from keyshare
		var localState tss.LocalState
		if err := json.Unmarshal(decodedKeyshare, &localState); err != nil {
			fmt.Printf("Failed to parse keyshare: %v\n", err)
			return
		}

		// Get the derived public key using chain code from keyshare
		btcPub, err := tss.GetDerivedPubKey(localState.PubKey, localState.ChainCodeHex, derivePath, false)
		if err != nil {
			fmt.Printf("Failed to get derived public key: %v\n", err)
			return
		}

		// Get the sender address
		senderAddress, err := tss.ConvertPubKeyToBTCAddress(btcPub, "testnet3")
		if err != nil {
			fmt.Printf("Failed to get sender address: %v\n", err)
			return
		}

		fmt.Printf("Successfully processed keyshare for %s\n", peer)

		// Get local nostr keys
		localNostrKeys, err := GetNostrKeys(peer)
		if err != nil {
			fmt.Printf("Error getting local nostr keys: %v\n", err)
			return
		}

		// Create TxRequest struct
		txRequest := tss.TxRequest{
			SenderAddress:   senderAddress,
			ReceiverAddress: receiverAddress,
			AmountSatoshi:   amountSatoshi,
			FeeSatoshi:      estimatedFee,
			DerivePath:      derivePath,
			BtcPub:          btcPub,
		}

		sessionID := randomSeed(64)
		sessionKey := randomSeed(64)

		// Use nostrSpend function
		result, err := tss.NostrSpend(nostrRelay, localNostrKeys.LocalNostrPubKey, localNostrKeys.LocalNostrPrivKey, parties, string(decodedKeyshare), txRequest, sessionID, sessionKey, "true", "true")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("\n [%s] NostrSpend Result %s\n", peer, result)
		}
		select {}
	}

	if mode == "ListenNostrMessages" {
		//Used for testing nostr MPCsendBTC
		//This is to be run first by each party.
		fmt.Println("ListenNostrMessages called")
		localNpub := os.Args[2]
		localNsec := os.Args[3]
		nostrRelay := os.Args[4]

		go tss.NostrListen(localNpub, localNsec, nostrRelay)
		time.Sleep(2 * time.Second)

		for {
			sessions, err := tss.GetSessions()
			if err != nil {
				fmt.Printf("Error getting sessions: %v\n", err)
				return
			}
			if len(sessions) > 0 {
				fmt.Printf("Sessions: %v\n", sessions[0])
				fmt.Printf("Sessions: %v\n", sessions[0].Status)
				if sessions[0].Status == "init_handshake" {

					// protoMessage := tss.ProtoMessage{
					// 	SessionID:       sessions[0].SessionID,
					// 	ChainCode:       sessions[0].ChainCode,
					// 	SessionKey:      sessions[0].SessionKey,
					// 	TxRequest:       sessions[0].TxRequest,
					// 	Master:          sessions[0].Master,
					// 	FunctionType:    "ack_handshake",
					// 	From:            localNpub,
					// 	FromNostrPubKey: localNpub,
					// 	Recipients:      []string{sessions[0].Master.MasterPubKey},
					// 	Participants:    []string{localNpub},
					// }
					keyshareFile := localNpub + ".ks"
					fmt.Printf("Keyshare file: %s\n", keyshareFile)
					keyshare, err := os.ReadFile(keyshareFile)
					if err != nil {
						fmt.Printf("Error reading keyshare file for %s: %v\n", localNpub, err)
						return
					}
					decodedKeyshare, err := base64.StdEncoding.DecodeString(string(keyshare))
					if err != nil {
						fmt.Printf("Failed to decode base64 keyshare: %v\n", err)
						return
					}

					// Get the public key and chain code from keyshare
					// var localState tss.LocalState
					// if err := json.Unmarshal(decodedKeyshare, &localState); err != nil {
					// 	fmt.Printf("Failed to parse keyshare: %v\n", err)
					// 	return
					// }
					partyNpubs := strings.Join(sessions[0].Participants, ",")
					fmt.Printf("Running NostrSpend for session: %v\n", partyNpubs)
					tss.NostrSpend(nostrRelay, localNpub, localNsec, partyNpubs, string(decodedKeyshare), sessions[0].TxRequest, sessions[0].SessionID, sessions[0].SessionKey, "true", "false")
					select {}
				}
			}
			time.Sleep(500 * time.Millisecond)

		}
		select {}

	}

	if mode == "nostrPing" {
		// Usage: go run main.go nostrPing <localParty> <recipientNpub>
		if len(os.Args) != 4 {
			fmt.Println("Usage: go run main.go nostrPing <localParty> <recipientNpub>")
			fmt.Println("Example: go run main.go nostrPing peer1 npub1abc123...")
			os.Exit(1)
		}

		localParty := os.Args[2]
		recipientNpub := os.Args[3]

		fmt.Printf("Sending Nostr ping from %s to %s...\n", localParty, recipientNpub)

		// Start Nostr listener in background
		go tss.NostrListen(localParty, nostrRelay, "localNostrKeys")
		time.Sleep(time.Second * 2) // Wait for listener to start

		// Send ping
		nostrPing(localParty, recipientNpub)
	}
}

func nostrPing(localParty, recipientNpub string) {
	_, err := tss.SendNostrPing(localParty, randomSeed(32), recipientNpub)
	if err != nil {
		fmt.Printf("Error sending ping: %v\n", err)
	}

}

func GetNostrKeys(party string) (tss.NostrKeys, error) {

	data, err := os.ReadFile(party + ".nostr")
	if err != nil {
		fmt.Printf("Go Error GetNostrKeys: %v\n", err)
		return tss.NostrKeys{}, err
	}

	// Create a temporary struct that matches the actual JSON structure
	type tempNostrKeys struct {
		LocalNostrPubKey  string            `json:"local_nostr_pub_key"`
		LocalNostrPrivKey string            `json:"local_nostr_priv_key"`
		NostrPartyPubKeys map[string]string `json:"nostr_party_pub_keys"`
	}

	var tempKeys tempNostrKeys
	if err := json.Unmarshal(data, &tempKeys); err != nil {
		fmt.Printf("Go Error Unmarshalling tempNostrKeys: %v\n", err)
		return tss.NostrKeys{}, err
	}

	// Convert the map values to a slice of strings
	var partyPubKeys []string
	for _, value := range tempKeys.NostrPartyPubKeys {
		partyPubKeys = append(partyPubKeys, value)
	}

	// Create the proper NostrKeys struct
	nostrKeys := tss.NostrKeys{
		LocalNostrPubKey:  tempKeys.LocalNostrPubKey,
		LocalNostrPrivKey: tempKeys.LocalNostrPrivKey,
		NostrPartyPubKeys: partyPubKeys,
	}

	return nostrKeys, nil
}

func GetKeyShare(party string) (tss.LocalState, error) {

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
	var keyShare tss.LocalState
	if err := json.Unmarshal(decodedData, &keyShare); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v\n", err)
	}

	return keyShare, nil
}
