package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"github.com/BoldBitcoinWallet/BBMTLib/tss"
)

func randomSeed(length int) string {
	const characters = "0123456789abcdef"
	result := make([]byte, length)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < length; i++ {
		result[i] = characters[r.Intn(len(characters))]
	}
	return string(result)
}

func main() {

	mode := os.Args[1]

	if mode == "keypair" {
		kp, _ := tss.GenerateKeyPair()
		fmt.Println(kp)
	}

	if mode == "random" {
		fmt.Println(randomSeed(64))
	}

	if mode == "relay" {
		port := os.Args[2]
		useNostr, err := strconv.ParseBool(os.Args[3])
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		}
		nostrRelay := os.Args[4]
		nostrPubKey := os.Args[5]
		nostrPrivKey := os.Args[6]
		defer tss.StopRelay()
		tss.RunRelay(port, useNostr, nostrRelay, nostrPubKey, nostrPrivKey)
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

		useNostr, err := strconv.ParseBool(os.Args[10])
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		}

		nostrRelay := os.Args[11]
		nostrPubKey := os.Args[12]
		nostrPrivKey := os.Args[13]
		nostrPartyPubKeys := os.Args[14]

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		ppmFile := party + ".json"
		keyshareFile := party + ".ks"

		//join keygen
		keyshare, err := tss.JoinKeygen(ppmFile, party, parties, encKey, decKey, session, server, chainCode, sessionKey, useNostr, nostrRelay, nostrPubKey, nostrPrivKey, nostrPartyPubKeys)
		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {

			// Create LocalState with Nostr keys

			var localState tss.LocalState

			if err := json.Unmarshal([]byte(keyshare), &localState); err != nil {

				fmt.Printf("Failed to parse keyshare for %s: %v\n", party, err)

			}

			var nostrPartyPubKeysMap struct {
				NostrPubKeys map[string]string `json:"nostr_party_pub_keys"`
			}
			if err := json.Unmarshal([]byte(nostrPartyPubKeys), &nostrPartyPubKeysMap); err != nil {
				fmt.Printf("Failed to parse nostr party pubkeys: %v\n", err)
			}
			localState.LocalNostrPubKey = nostrPubKey
			localState.LocalNostrPrivKey = nostrPrivKey
			localState.NostrPartyPubKeys = nostrPartyPubKeysMap.NostrPubKeys
			//var peer1 = localState.NostrPartyPubKeys["peer1"]

			// Marshal the updated LocalState
			updatedKeyshare, err := json.Marshal(localState)

			if err != nil {

				fmt.Printf("Failed to marshal updated keyshare for %s: %v\n", party, err)

			}

			// save keyshare file - base64 encoded

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
					fmt.Printf(party+" Nostr Party PubKeys: %s\n", nostrPartyPubKeys)

					// Master host is the party with the largest nostr public key
					var maxPeer string
					var maxKey string
					for peer, key := range localState.NostrPartyPubKeys {
						if key > maxKey { // Direct string comparison
							maxKey = key
							maxPeer = peer
						}
					}
					fmt.Printf("Master host of the party is : %s: %s\n", maxPeer, maxKey)
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

		if len(sessionKey) > 0 {
			encKey = ""
			decKey = ""
		}

		// message hash, base64 encoded
		messageHash, _ := tss.Sha256(message)
		messageHashBytes := []byte(messageHash)
		messageHashBase64 := base64.StdEncoding.EncodeToString(messageHashBytes)

		// join keysign
		keysign, err := tss.JoinKeysign(server, party, parties, session, sessionKey, encKey, decKey, keyshare, derivePath, messageHashBase64)
		time.Sleep(time.Second)

		if err != nil {
			fmt.Printf("Go Error: %v\n", err)
		} else {
			fmt.Printf("\n [%s] Keysign Result %s\n", party, keysign)
		}
	}
}
