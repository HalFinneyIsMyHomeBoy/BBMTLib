package main

import (
	"fmt"
	"math/rand"
	"os"
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
		defer tss.StopRelay()
		tss.RunRelay(port)
		select {}
	}

	if mode == "keygen" {
		server := os.Args[2]
		session := os.Args[3]
		chainCode := os.Args[4]
		party := os.Args[5]
		parties := os.Args[6]
		encKey := os.Args[7]
		decKey := os.Args[8]
		sessionKey := ""
		ppmFile := party + ".json"
		keygen, err := tss.JoinKeygen(ppmFile, party, parties, encKey, decKey, session, server, chainCode, sessionKey)
		if err != nil {
			fmt.Printf("Go Error: %v", err)
		} else {
			fmt.Printf("Peer2 Keygen Result:" + keygen)
		}
	}
}
