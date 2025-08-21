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
		allPubKeys := make([]string, 0)

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
			allPubKeys = append(allPubKeys, npub)
			fmt.Printf("Successfully generated keys for %s\n", peerName)
		}

		// Create individual .nostr files for each peer
		// Ensure the scripts/ directory exists
		fmt.Println("\nCreating .nostr files...")
		for i := 1; i <= numPeers; i++ {
			peerName := fmt.Sprintf("peer%d", i)
			fmt.Printf("Creating file for %s...\n", peerName)

			nostrConfig := struct {
				LocalNostrPubKey  string   `json:"local_nostr_pub_key"`
				LocalNostrPrivKey string   `json:"local_nostr_priv_key"`
				NostrPartyPubKeys []string `json:"nostr_party_pub_keys"`
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
		localNpub := "npub1p0dj3g82ff56prwnw4kkvphuv6ej25y9d2nr076795x6kescjefs7d2gqm"
		localNsec := "nsec1hqneu0zle0tu8hk605hm2v384qxqla7v97qdz8nzqjerzefc0wmqg8fftz"
		//remote "nsec12p2mh25m5frvncwwmglrrjt3t2mrpctl4x6kpzkl6nr2g5gw806sjhefv6"
		partyNpubs := "npub1p0dj3g82ff56prwnw4kkvphuv6ej25y9d2nr076795x6kescjefs7d2gqm,npub132gndqvcqyrvuu2q3lwg363cadmg2l7emqd36lawr3ey068slafqvrmknn,npub1rxnfxtrcfg49u3zptgc30ywf862mjfehn9x0rdu06yef8nr7phksrghwdq"
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
		localNpub := "npub15qt3jlzgrek4st5sltuju5z2q5kcrk6p72k8vduv273gc8seg72q6lmnnh"
		localNsec := "nsec1jwa0mcque2dn6nfx8r92znctxhu960wlzkx0f97hg2at0mxnzvqsssguva"

		partyNpubs := "npub15qt3jlzgrek4st5sltuju5z2q5kcrk6p72k8vduv273gc8seg72q6lmnnh,npub1u9qehjkswj9jzx2j5ex89h0qsd2pdjg33mde49ujn0e8y0nunp7q3s6msv,npub190szmjnpt6xpu8rxg8xmy2w7g5s7alncl0hgamq9pv9dpskgq8msedy03l"
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
			Master:          tss.Master{MasterPeer: localNpub, MasterPubKey: localNpub},
		}

		sessionID := "8dd15291d0d60b2c0c4891e91d5f2832431fd21b49a5b9b6e06e228dc22c3b88"
		sessionKey := "7dd15291d0d60b2c0c4891e91d5f2832431fd21b49a5b9b6e06e228dc22c3b87"

		go tss.NostrListen(localNpub, localNsec, nostrRelay)
		time.Sleep(2 * time.Second)
		fmt.Printf("NostrListen started for %s\n", localNpub)

		sessions, err := tss.WaitForSessions()
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("Sessions: %v\n", sessions)
			sessionID = sessions[0].SessionID
			sessionKey = sessions[0].SessionKey
			partyNpubs = strings.Join(sessions[0].Participants, ",")
			txRequest.Master.MasterPeer = sessions[0].Master.MasterPeer
			txRequest.Master.MasterPubKey = sessions[0].Master.MasterPubKey
			txRequest.DerivePath = sessions[0].TxRequest.DerivePath
			txRequest.BtcPub = sessions[0].TxRequest.BtcPub
			txRequest.SenderAddress = sessions[0].TxRequest.SenderAddress
			txRequest.ReceiverAddress = sessions[0].TxRequest.ReceiverAddress
			txRequest.AmountSatoshi = sessions[0].TxRequest.AmountSatoshi
			txRequest.FeeSatoshi = sessions[0].TxRequest.FeeSatoshi

			result, err := tss.NostrSpend(nostrRelay, localNpub, localNsec, partyNpubs, string(keyshare), txRequest, sessionID, sessionKey, "true", "true")
			if err != nil {
				fmt.Printf("Go Error: %v\n", err)
			} else {
				fmt.Printf("Keygen Result: %s\n", result)
			}

		}

		select {}
	}

	if mode == "nostrSpend" {
		fmt.Println("nostrSpend called")
		localNpub := os.Args[2]
		localNsec := os.Args[3]
		partyNpubs := os.Args[4]
		nostrRelay := os.Args[5]
		sessionID := os.Args[6]
		sessionKey := os.Args[7]
		receiverAddress := os.Args[8]
		derivePath := os.Args[9]
		amountSatoshi, err := strconv.ParseInt(os.Args[10], 10, 64)
		if err != nil {
			fmt.Printf("Invalid amountSatoshi: %v\n", err)
			return
		}
		estimatedFee, err := strconv.ParseInt(os.Args[11], 10, 64)
		if err != nil {
			fmt.Printf("Invalid estimatedFee: %v\n", err)
			return
		}
		partyIndex, err := strconv.Atoi(os.Args[12])
		if err != nil {
			fmt.Printf("Invalid partyIndex: %v\n", err)
			return
		}
		masterNpub := os.Args[13]

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

		txRequest := tss.TxRequest{
			SenderAddress:   senderAddress,
			ReceiverAddress: receiverAddress,
			AmountSatoshi:   amountSatoshi,
			FeeSatoshi:      estimatedFee,
			DerivePath:      derivePath,
			BtcPub:          btcPub,
			Master:          tss.Master{MasterPeer: masterNpub, MasterPubKey: masterNpub},
		}

		go tss.NostrListen(localNpub, localNsec, nostrRelay)
		time.Sleep(2 * time.Second)
		fmt.Printf("NostrListen started for %s\n", localNpub)

		if partyIndex == 0 {
			//Master party is the first party to initiate the session, so newSession is passed as true.
			tss.NostrSpend(nostrRelay, localNpub, localNsec, partyNpubs, string(decodedKeyshare), txRequest, sessionID, sessionKey, "false", "true")
		} else {
			//Non-master parties are passing newSession as false if they approve the session.
			tss.NostrSpend(nostrRelay, localNpub, localNsec, partyNpubs, string(decodedKeyshare), txRequest, sessionID, sessionKey, "true", "false")
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
