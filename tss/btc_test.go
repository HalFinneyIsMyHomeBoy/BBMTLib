package tss

import (
	"encoding/json"
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func TestCreateAddress(t *testing.T) {
	Logln("creating wallet")
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Get the public key
	publicKey := privateKey.PubKey()

	// Convert the public key to a Bitcoin address for testnet3
	pubKeyHash := btcutil.Hash160(publicKey.SerializeCompressed())
	address, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("Failed to generate Bitcoin address: %v", err)
	}

	// Encode the private key in WIF format
	wifKey, err := btcutil.NewWIF(privateKey, &chaincfg.TestNet3Params, true)
	if err != nil {
		log.Fatalf("Error encoding WIF: %v", err)
	}

	// Print the values
	Logln("Private Key (WIF): %s\n", wifKey)
	Logln("Public Key: %x\n", publicKey.SerializeCompressed())
	Logln("Bitcoin Address (testnet3): %s\n", address.EncodeAddress())

	/*
		Private Key (WIF): cT3tu4QnwzRZe7oGMeQ8k9K5t3z1UAGD1FxJvzJmLz9aTJYfHi1h
		Public Key: 037137cb63cf474bb07fb25cc5678d5981f4fee3244a6dd51a041113ca5192c00a
		Bitcoin Address (testnet3): mhEypteu3dE2rRqwtsQxWDMiVEHEqtxER6
	*/
}

func TestAddress(t *testing.T) {

	address := "mhEypteu3dE2rRqwtsQxWDMiVEHEqtxER6"

	utxos, err := FetchUTXOs(address)
	if err != nil {
		Logln("Error fetching UTXOs:", err)
		return
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(utxos, "", "  ")
	if err != nil {
		log.Fatalf("Error converting to JSON: %v", err)
	}

	// Print JSON
	Logln(string(jsonData))

	feeRate, err := RecommendedFees("30m")
	if err != nil {
		Logln("Error fetching fee rate:", err)
		return
	}
	Logln("fee_rate", feeRate)
}

func TestSend(t *testing.T) {
	// Running tool: /opt/homebrew/opt/go/libexec/bin/go test -timeout 30s -run ^TestSend$

	wif := "cT3tu4QnwzRZe7oGMeQ8k9K5t3z1UAGD1FxJvzJmLz9aTJYfHi1h"
	senderAddress := "mhEypteu3dE2rRqwtsQxWDMiVEHEqtxER6"
	senderPub := "037137cb63cf474bb07fb25cc5678d5981f4fee3244a6dd51a041113ca5192c00a"
	// receiverAddress := "muEbnp4xHnbAfBwK9BU6dzp5dWGcVX24qT"
	//receiverAddress = "tb1qahppd6dcsc9rrhsdteqfe2as8cfgjzzfm4vv4n"
	receiverAddress := "mrATkhfzzHL3aLUxCk6xDws9ZaMGrxrFqt"
	amountSatoshi := int64(10000)

	fee, err := SendBitcoin(wif, senderPub, senderAddress, receiverAddress, 1, amountSatoshi)
	if err != nil {
		log.Fatalf("Failed to estimate fee bitcoin: %v", err)
	}
	Logf("Estimated Fee %s", fee)

	txid, err := SendBitcoin(wif, senderPub, senderAddress, receiverAddress, 0, amountSatoshi)
	if err != nil {
		log.Fatalf("Failed to send bitcoin: %v", err)
	}
	Logf("Transaction successful! TXID: %s", txid)
}
