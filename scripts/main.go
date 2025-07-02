package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/BoldBitcoinWallet/BBMTLib/tss"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

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

	var nostrRelay string
	nostrRelay = "ws://bbw-nostr.xyz"

	mode := os.Args[1]

	if mode == "keypair" {
		kp, _ := tss.GenerateKeyPair()
		fmt.Println(kp)
	}

	if mode == "generateNostrKeys" {
		fmt.Println("Starting Nostr peer generation...")
		// Generate 3 keypairs
		peerKeys := make(map[string]map[string]string)
		allPubKeys := make(map[string]string)

		// Generate keys for 3 peers
		for i := 1; i <= 3; i++ {
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
		os.MkdirAll("scripts", 0755)
		fmt.Println("\nCreating .nostr files...")
		for i := 1; i <= 3; i++ {
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

	if mode == "relay" {
		port := os.Args[2]
		defer tss.StopRelay()
		tss.RunRelay(port)
		select {}
	}

	if mode == "nostrKeygen" {
		// prepare args

		parties := "peer1,peer2,peer3" // All participating parties
		session := randomSeed(64)      // Generate random session ID
		sessionKey := randomSeed(64)   // Random session key
		chainCode := randomSeed(64)
		server := "http://127.0.0.1:55055"

		net_type := "nostr"
		peer := "peer1"

		ppmFile := peer + ".json"
		keyshareFile := peer + ".ks"
		nostrKeysFile := peer + ".nostr"
		var err error

		if net_type == "nostr" {
			net_type = "nostr"
			go tss.NostrListen(peer, nostrRelay)
			time.Sleep(time.Second * 2)
		}

		// Check if .nostr file exists
		if _, err := os.Stat(nostrKeysFile); err == nil {
			fmt.Printf("Existing Nostr keys found for %s\n", peer)
		}

		//join keygen
		keyshare, err := tss.JoinKeygen(ppmFile, peer, parties, "", "", session, server, chainCode, sessionKey, net_type, "true")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {

			// Create LocalState with Nostr keys
			var localState tss.LocalState

			if err := json.Unmarshal([]byte(keyshare), &localState); err != nil {
				fmt.Printf("Failed to parse keyshare for %s: %v\n", peer, err)
			}

			// // Marshal the updated LocalState
			updatedKeyshare, err := json.Marshal(localState)
			fmt.Printf(peer + " Keygen Result Saved\n")
			encodedResult := base64.StdEncoding.EncodeToString(updatedKeyshare)

			if err := os.WriteFile(keyshareFile, []byte(encodedResult), 0644); err != nil {
				fmt.Printf("Failed to save keyshare for %s: %v\n", peer, err)
			}

			var kgR tss.KeygenResponse
			if err := json.Unmarshal([]byte(keyshare), &kgR); err != nil {
				fmt.Printf("Failed to parse keyshare for %s: %v\n", peer, err)
			}

			// print out pubkeys and p2pkh address
			fmt.Printf(peer+" Public Key: %s\n", kgR.PubKey)
			xPub := kgR.PubKey
			btcPath := "m/44'/0'/0'/0/0"
			btcPub, err := tss.GetDerivedPubKey(xPub, chainCode, btcPath, false)
			if err != nil {
				fmt.Printf("Failed to generate btc pubkey for %s: %v\n", peer, err)
			} else {
				fmt.Printf(peer+" BTC Public Key: %s\n", btcPub)
				btcP2Pkh, err := tss.ConvertPubKeyToBTCAddress(btcPub, "testnet3")
				if err != nil {
					fmt.Printf("Failed to generate btc address for %s: %v\n", peer, err)
				} else {
					fmt.Printf(peer+" address btcP2Pkh: %s\n", btcP2Pkh)
					//fmt.Printf(party+" Nostr Party PubKeys: %s\n", nostrPartyPubKeys)
				}
			}
		}
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

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		ppmFile := party + ".json"
		keyshareFile := party + ".ks"

		//join keygen
		keyshare, err := tss.JoinKeygen(ppmFile, party, parties, encKey, decKey, session, server, chainCode, sessionKey, "", "false")
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

	if mode == "nostrSendBTC" {

		//This is to be called by the party initiating the session to send BTC
		//The party to initiate this is the master by default for the session.

		fmt.Println("InitiateNostrSendBTC called")
		parties := "peer1,peer2,peer3" // All participating parties
		session := randomSeed(64)      // Generate random session ID
		sessionKey := randomSeed(64)   // Random session key
		derivePath := "m/44'/0'/0'/0/0"
		receiverAddress := "mt1KTSEerA22rfhprYAVuuAvVW1e9xTqfV"
		amountSatoshi := 1000
		estimatedFee := 600
		peer := "peer1"
		net_type := "nostr"

		if net_type == "nostr" {
			net_type = "nostr"
			go tss.NostrListen(peer, nostrRelay)
			time.Sleep(time.Second * 2)
		} else {
			go tss.RunRelay("55055")
			time.Sleep(time.Second)
		}

		fmt.Printf("Processing peer: %s\n", peer)
		keyshareFile := peer + ".ks"

		// Read and decode keyshare file for this peer
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

		fmt.Println("Testing...")
		// prepare args
		server := "http://127.0.0.1:55055" // Default relay server

		// Generate keypair for encryption/decryption
		keypair, err := tss.GenerateKeyPair()
		if err != nil {
			fmt.Printf("Error generating keypair: %v\n", err)
			return
		}
		var keypairMap map[string]string
		if err := json.Unmarshal([]byte(keypair), &keypairMap); err != nil {
			fmt.Printf("Error parsing keypair: %v\n", err)
			return
		}
		encKey := keypairMap["PublicKey"]  // Public key for encryption
		decKey := keypairMap["PrivateKey"] // Private key for decryption

		derivePath = "m/44'/0'/0'/0/0" // Standard BTC derivation path

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		result, err := tss.MpcSendBTC(server, peer, parties, session, sessionKey, encKey, decKey, string(keyshare), derivePath, btcPub, senderAddress, receiverAddress, int64(amountSatoshi), int64(estimatedFee), net_type, "true")
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("\n [%s] Keysign Result %s\n", peer, result)
		}

	}

	if mode == "ListenNostrMessages" {
		//Used for testing nostr MPCsendBTC
		//This is to be run first by each party.
		fmt.Println("ListenNostrMessages called")
		localParty := os.Args[2]
		net_type := "nostr"

		if net_type == "nostr" {
			go tss.NostrListen(localParty, nostrRelay)
			//time.Sleep(time.Second * 2)
			//nostrPing(localParty, recipientNpub)
			select {}
		}
	}
}

func nostrPing(localParty, recipientNpub string) {
	ping, err := tss.SendNostrPing(localParty, randomSeed(32), recipientNpub)
	if err != nil {
		fmt.Printf("Error sending ping: %v\n", err)
	}
	if ping {
		fmt.Printf("Ping sent to %s\n", recipientNpub)
	}
	if !ping {
		fmt.Printf("Peer not responding %s\n", recipientNpub)
	}
}

func GetNostrKeys(party string) (tss.NostrKeys, error) {

	data, err := os.ReadFile(party + ".nostr")
	if err != nil {
		fmt.Printf("Go Error GetNostrKeys: %v\n", err)
	}

	var nostrKeys tss.NostrKeys
	if err := json.Unmarshal(data, &nostrKeys); err != nil {
		fmt.Printf("Go Error Unmarshalling LocalState: %v\n", err)
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
