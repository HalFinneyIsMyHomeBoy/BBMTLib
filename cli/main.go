package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"

	"github.com/agiledragon/gomonkey/v2"

	"github.com/BoldBitcoinWallet/BBMTLib/tss"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	ipfslog "github.com/ipfs/go-log"
)

const (
	AppPrimaryName = "BoldFuze CLI"
	AppAltName     = "BF-CLI"
	AppVersion     = "1.0.0"
)

// Command represents a CLI command with its handler and usage information
type Command struct {
	Name        string
	Description string
	Usage       string
	Handler     func(args []string) error
}

// CLI represents the command-line interface
type CLI struct {
	commands map[string]Command
	verbose  bool
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	return &CLI{
		commands: make(map[string]Command),
	}
}

// setupLogging configures logging based on verbose flag
func (c *CLI) setupLogging() {
	if !c.verbose {
		// Monkey-patch ipfs/go-log logger used by tss-lib to no-op
		var patches *gomonkey.Patches = gomonkey.NewPatches()

		loggerType := reflect.TypeOf(&ipfslog.ZapEventLogger{})
		// No-op formatted methods
		patches.ApplyMethod(loggerType, "Infof", func(_ *ipfslog.ZapEventLogger, _ string, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Debugf", func(_ *ipfslog.ZapEventLogger, _ string, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Warnf", func(_ *ipfslog.ZapEventLogger, _ string, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Errorf", func(_ *ipfslog.ZapEventLogger, _ string, _ ...interface{}) {})
		// No-op unformatted methods
		patches.ApplyMethod(loggerType, "Info", func(_ *ipfslog.ZapEventLogger, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Debug", func(_ *ipfslog.ZapEventLogger, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Warn", func(_ *ipfslog.ZapEventLogger, _ ...interface{}) {})
		patches.ApplyMethod(loggerType, "Error", func(_ *ipfslog.ZapEventLogger, _ ...interface{}) {})

		patches.ApplyFunc(tss.Logf, func(_ string, _ ...any) {})
		patches.ApplyFunc(tss.Logln, func(_ ...any) {})
		defer patches.Reset()

		tss.DisableLogs()
	}
}

// RegisterCommand adds a command to the CLI
func (c *CLI) RegisterCommand(cmd Command) {
	c.commands[cmd.Name] = cmd
}

// ShowHelp displays help information
func (c *CLI) ShowHelp() {
	useColor := supportsColor()

	bold := func(s string) string {
		if useColor {
			return "\033[1m" + s + "\033[0m"
		}
		return s
	}
	cyan := func(s string) string {
		if useColor {
			return "\033[36m" + s + "\033[0m"
		}
		return s
	}
	green := func(s string) string {
		if useColor {
			return "\033[32m" + s + "\033[0m"
		}
		return s
	}
	dim := func(s string) string {
		if useColor {
			return "\033[2m" + s + "\033[0m"
		}
		return s
	}

	fmt.Printf("%s\n%s v%s\n\n", bold(AppPrimaryName), AppAltName, AppVersion)
	fmt.Printf("Website: %s\n\n", "https://boldbitcoinwallet.com")
	fmt.Println(bold("Available commands:"))
	fmt.Println()

	groups := []struct {
		title   string
		members []string
	}{
		{"Crypto-Common", []string{"random-seed", "ecies-keypair", "ecies-encrypt", "ecies-decrypt"}},
		{"TSS-Common", []string{"derive-address", "preparams"}},
		{"HTTP-MPC-TSS", []string{"http-relay", "http-keygen", "http-keysign", "http-spend"}},
		{"NOSTR-MPC-TSS", []string{"nostr-keypair", "nostr-keygen", "nostr-keysign", "nostr-spend"}},
	}

	for _, group := range groups {
		fmt.Printf("  %s\n", cyan(bold(group.title)))
		for _, name := range group.members {
			if cmd, ok := c.commands[name]; ok {
				fmt.Printf("    %-20s %s\n", green(cmd.Name), cmd.Description)
				if cmd.Usage != "" {
					fmt.Printf("      %s: %s\n", dim("Usage"), cmd.Usage)
				}
				fmt.Println()
			}
		}
	}
}

// supportsColor returns whether we should print ANSI colors
func supportsColor() bool {
	// disable if NO_COLOR is set or TERM is dumb
	if len(os.Getenv("NO_COLOR")) > 0 {
		return false
	}
	term := os.Getenv("TERM")
	if term == "dumb" || term == "" {
		return false
	}
	return true
}

// Execute runs the CLI with the given arguments
func (c *CLI) Execute(args []string) error {
	if len(args) < 2 {
		c.ShowHelp()
		return fmt.Errorf("no command specified")
	}

	// Check for verbose flag
	c.verbose = len(args) > 2 && args[len(args)-1] == "verbose"
	if c.verbose {
		args = args[:len(args)-1] // Remove trailing legacy verbose token
	} else {
		filtered := make([]string, 0, len(args))
		for _, a := range args {
			if a == "--verbose" {
				c.verbose = true
				continue
			}
			filtered = append(filtered, a)
		}
		args = filtered
	}

	c.setupLogging()

	// expose verbose to command handlers
	globalVerbose = c.verbose

	command := args[1]
	cmdArgs := args[2:]

	if cmd, exists := c.commands[command]; exists {
		return cmd.Handler(cmdArgs)
	}

	return fmt.Errorf("unknown command: %s", command)
}

// global verbose flag for handlers
var globalVerbose bool

// currentCLI allows help handler to inspect registered commands
var currentCLI *CLI

// parseFlags parses --key=value and --key value pairs and returns flags map and remaining positional args
func parseFlags(args []string) (map[string]string, []string) {
	flags := make(map[string]string)
	positional := make([]string, 0, len(args))
	i := 0
	for i < len(args) {
		a := args[i]
		if len(a) > 2 && a[:2] == "--" {
			kv := a[2:]
			if eq := indexByte(kv, '='); eq >= 0 {
				key := kv[:eq]
				val := kv[eq+1:]
				flags[key] = val
				i++
				continue
			}
			if i+1 < len(args) && !(len(args[i+1]) > 0 && args[i+1][0] == '-') {
				flags[kv] = args[i+1]
				i += 2
				continue
			}
			flags[kv] = "true"
			i++
		} else {
			positional = append(positional, a)
			i++
		}
	}
	return flags, positional
}

// indexByte returns the index of c in s or -1
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// pick returns flag value by key if present, otherwise positional at posIndex
func pick(flags map[string]string, key string, positional []string, posIndex int, def string) string {
	if v, ok := flags[key]; ok {
		return v
	}
	if posIndex >= 0 && posIndex < len(positional) {
		return positional[posIndex]
	}
	return def
}

// Handlers (preserve original logic, adapted to args[])

func handleEciesKeypair(_ []string) error {
	kp, _ := tss.GenerateKeyPair()
	tss.Stdout(kp)
	return nil
}

func handleEciesEncrypt(args []string) error {
	flags, pos := parseFlags(args)
	if len(flags) > 0 {
		data := pick(flags, "data", nil, -1, "")
		publicKey := pick(flags, "public-key", nil, -1, "")
		if data == "" || publicKey == "" {
			return fmt.Errorf("usage: ecies-encrypt --data <data> --public-key <publicKey>")
		}
		encryptedData, _ := tss.EciesEncrypt(data, publicKey)
		tss.Stdout(encryptedData)
		return nil
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: ecies-encrypt <data> <publicKey>")
	}
	data := pos[0]
	publicKey := pos[1]
	encryptedData, _ := tss.EciesEncrypt(data, publicKey)
	tss.Stdout(encryptedData)
	return nil
}

func handleEciesDecrypt(args []string) error {
	flags, pos := parseFlags(args)
	if len(flags) > 0 {
		encryptedData := pick(flags, "encrypted-data", nil, -1, "")
		privateKey := pick(flags, "private-key", nil, -1, "")
		if encryptedData == "" || privateKey == "" {
			return fmt.Errorf("usage: ecies-decrypt --encrypted-data <data> --private-key <key>")
		}
		decryptedData, _ := tss.EciesDecrypt(encryptedData, privateKey)
		tss.Stdout(decryptedData)
		return nil
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: ecies-decrypt <encryptedData> <privateKey>")
	}
	encryptedData := pos[0]
	privateKey := pos[1]
	decryptedData, _ := tss.EciesDecrypt(encryptedData, privateKey)
	tss.Stdout(decryptedData)
	return nil
}

func handlePreparams(args []string) error {
	flags, pos := parseFlags(args)
	ppm := ""
	if len(flags) > 0 {
		ppm = pick(flags, "ppm", nil, -1, "")
		if ppm == "" {
			return fmt.Errorf("usage: preparams --ppm <file>")
		}
	} else {
		if len(pos) != 1 {
			return fmt.Errorf("usage: preparams <ppm>")
		}
		ppm = pos[0]
	}
	preParams, err := tss.PreParams(ppm)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to generate preparams: %v\n", err))
		return nil
	}
	output, err := json.Marshal(preParams)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to marshal preparams%v\n", err))
		return nil
	} else if len(ppm) > 0 {
		tss.Stdout("generate to file: " + ppm)
	} else {
		tss.Stdout(string(output))
	}
	return nil
}

func handleNostrKeypair(_ []string) error {
	privateKey := nostr.GeneratePrivateKey()
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		tss.Stdout(fmt.Sprintf("Error generating public key: %v\n", err))
		return nil
	}

	nsec, err := nip19.EncodePrivateKey(privateKey)
	if err != nil {
		tss.Stdout(fmt.Sprintf("Error encoding private key: %v\n", err))
		return nil
	}

	npub, err := nip19.EncodePublicKey(publicKey)
	if err != nil {
		tss.Stdout(fmt.Sprintf("Error encoding public key: %v\n", err))
		return nil
	}
	keyPair := map[string]string{
		"privateKey": nsec,
		"publicKey":  npub,
	}
	keyPairJSON, _ := json.Marshal(keyPair)
	tss.Stdout(string(keyPairJSON))
	return nil
}

func handleRandomSeed(args []string) error {
	flags, pos := parseFlags(args)
	length := 64
	var err error
	if len(flags) > 0 {
		if v, ok := flags["length"]; ok {
			length, err = strconv.Atoi(v)
			if err != nil {
				tss.Stderr(fmt.Sprintf("Usage: random-seed --length <32|64|128|256>: %v\n", err))
				return nil
			}
		}
	} else if len(pos) > 0 {
		length, err = strconv.Atoi(pos[0])
		if err != nil {
			tss.Stderr(fmt.Sprintf("Usage: random-seed <length: 32, 64 default, 128, 256>: %v\n", err))
			return nil
		}
	}
	out, err := tss.SecureRandom(length)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Error: %v\n", err))
		return nil
	}
	tss.Stdout(out)
	return nil
}

func handleDeriveAddress(args []string) error {
	if len(args) < 5 || len(args) > 5 { // preserve strict original check len==5 after mode
		// original required 6 additional args including program name and mode: we enforce 5 here
		tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: optional-default m/44'/0'/0'/0/0>")
		return nil
	}
	network := args[0]
	addressType := args[1]
	pubKey := args[2]
	chainCode := args[3]
	path := "m/44'/0'/0'/0/0"
	if len(args) > 4 {
		path = args[4]
	}
	btcPub, err := tss.GetDerivedPubKey(pubKey, chainCode, path, false)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Error: %v\n", err))
		tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: default m/44'/0'/0'/0/0>")
		return nil
	}
	address := ""
	switch addressType {
	case "legacy":
		address, err = tss.PubToP2KH(btcPub, network)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Error: %v\n", err))
			tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: default m/44'/0'/0'/0/0>")
			return nil
		}
	case "segwit-compatible":
		address, err = tss.PubToP2WPKH(btcPub, network)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Error: %v\n", err))
			tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: default m/44'/0'/0'/0/0>")
			return nil
		}
	case "segwit-native":
		address, err = tss.PubToP2SHP2WKH(btcPub, network)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Error: %v\n", err))
			tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: default m/44'/0'/0'/0/0>")
			return nil
		}
	default:
		tss.Stderr(fmt.Sprintf("Error: %v\n", "Invalid address type"))
		tss.Stderr("Usage: derive-address <network: mainnet, testnet3> <type: legacy, segwit-compatible, segwit-native> <xpub> <chaincode> <path: default m/44'/0'/0'/0/0>")
		return nil
	}
	tss.Stdout(address)
	return nil
}

func handleHttpRelay(args []string) error {
	if len(args) != 1 {
		tss.Stderr("Usage: http-relay <port>")
		return nil
	}
	port := args[0]
	defer tss.StopRelay()
	tss.RunRelay(port)
	tss.Stdout(fmt.Sprintf("HTTP Relay started on port %s", port))
	select {}
}

func handleHttpKeygen(args []string) error {
	if len(args) < 9 {
		return fmt.Errorf("usage: http-keygen <server> <session> <chainCode> <party> <parties> <encKey> <decKey> <sessionKey> <ppm> [save] [passphrase]")
	}
	server := args[0]
	session := args[1]
	chainCode := args[2]
	party := args[3]
	parties := args[4]
	encKey := args[5]
	decKey := args[6]
	sessionKey := args[7]
	ppm := args[8]
	save := ""
	passphrase := ""
	net_type := "http"
	if len(sessionKey) > 0 {
		encKey = ""
		decKey = ""
		tss.Logln("Session key used for keygen")
	}
	if len(args) > 9 {
		save = args[9]
	}
	if len(args) > 10 {
		passphrase = args[10]
	}
	keyshare, err := tss.JoinKeygen(ppm, party, parties, encKey, decKey, session, server, chainCode, sessionKey, net_type)
	if err != nil {
		tss.Logf("JoinKeygen Error: %v\n", err)
		return nil
	}
	var localState tss.LocalState
	if err := json.Unmarshal([]byte(keyshare), &localState); err != nil {
		tss.Stderr(fmt.Sprintf("Failed to parse keyshare for %s: %v\n", party, err))
		return nil
	}
	updatedKeyshare, err := json.Marshal(localState)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to marshal keyshare for %s: %v\n", party, err))
		return nil
	}
	tss.Logf("%s Keygen Result Saved\n", party)
	content := keyshare
	switch save {
	case "base64":
		content = base64.StdEncoding.EncodeToString(updatedKeyshare)
		tss.Stdout(content)
	case "save":
		keyshareFile := party + ".ks"
		if len(passphrase) > 0 {
			hashPass, _ := tss.Sha256(passphrase)
			content, _ = tss.AesEncrypt(content, hashPass)
		}
		if err := os.WriteFile(keyshareFile, []byte(content), 0644); err != nil {
			fmt.Printf("Failed to save keyshare for %s: %v\n", party, err)
			return nil
		}
		tss.Stdout("saved: " + keyshareFile)
	default:
		tss.Stdout(keyshare)
	}
	return nil
}

func handleHttpKeysign(args []string) error {
	if len(args) < 10 {
		return fmt.Errorf("usage: http-keysign <server> <session> <party> <parties> <encKey> <decKey> <keyshare> <derivePath> <message> <sessionKey> <passphrase>")
	}
	server := args[0]
	session := args[1]
	party := args[2]
	parties := args[3]
	encKey := args[4]
	decKey := args[5]
	keyshare := args[6]
	derivePath := args[7]
	message := args[8]
	sessionKey := args[9]
	passphrase := ""
	if len(args) > 10 {
		passphrase = args[10]
	}
	if len(sessionKey) > 0 {
		encKey = ""
		decKey = ""
		tss.Logln("Session key used for keysign")
	}
	if len(passphrase) > 0 {
		tss.Logln("Decrypting keyshare")
		hashpass, _ := tss.Sha256(passphrase)
		keyshare, _ = tss.AesDecrypt(keyshare, hashpass)
	}
	messageHash, _ := tss.Sha256(message)
	messageHashBytes := []byte(messageHash)
	messageHashBase64 := base64.StdEncoding.EncodeToString(messageHashBytes)
	net_type := "http"
	keysign, err := tss.JoinKeysign(server, party, parties, session, sessionKey, encKey, decKey, keyshare, derivePath, messageHashBase64, net_type)
	if err != nil {
		tss.Stderr(fmt.Sprintf("JoinKeysign Error: %v\n", err))
		return nil
	}
	tss.Stdout(keysign)
	return nil
}

func handleHttpSpend(args []string) error {
	if len(args) < 14 {
		return fmt.Errorf("usage: http-spend <server> <session> <party> <parties> <encKey> <decKey> <sessionKey> <senderAddress> <receiverAddress> <derivePath> <amountSatoshi> <estimatedFee> <keyshare> [passphrase]")
	}

	server := args[0]
	sessionID := args[1]
	party := args[2]
	parties := args[3]
	encKey := args[4]
	decKey := args[5]
	sessionKey := args[6]
	senderAddress := args[7]
	receiverAddress := args[8]
	derivePath := args[9]
	amountSatoshi, err := strconv.ParseInt(args[10], 10, 64)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Invalid amountSatoshi: %v\n", err))
		return nil
	}
	estimatedFee, err := strconv.ParseInt(args[11], 10, 64)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Invalid estimatedFee: %v\n", err))
		return nil
	}
	keyshare := args[12]
	passphrase := ""
	if len(args) > 13 && args[13] != "verbose" {
		passphrase = args[13]
	}
	if len(passphrase) > 0 {
		tss.Logln("Decrypting keyshare")
		hashpass, err := tss.Sha256(passphrase)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to hash: %v\n", err))
			return nil
		}
		keyshare, err = tss.AesDecrypt(keyshare, hashpass)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to AesDecrypt: %v\n", err))
			return nil
		}
		tss.Logln("Decrypted Keyshare:" + keyshare)
	} else {
		decodedKeyshare, err := base64.StdEncoding.DecodeString(keyshare)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to decode base64 keyshare: %v\n", err))
			return nil
		}
		keyshare = string(decodedKeyshare)
	}

	var localState tss.LocalState
	if err := json.Unmarshal(([]byte(keyshare)), &localState); err != nil {
		tss.Stderr(fmt.Sprintf("Failed to parse keyshare: %v\n", err))
		return nil
	}

	btcPub, err := tss.GetDerivedPubKey(localState.PubKey, localState.ChainCodeHex, derivePath, false)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to get derived public key: %v\n", err))
		return nil
	}
	result, err := tss.MpcSendBTC(
		server, party, parties, sessionID, sessionKey, encKey, decKey,
		keyshare, derivePath, btcPub,
		senderAddress, receiverAddress, amountSatoshi, estimatedFee,
		"http",
	)
	if err != nil {
		tss.Stdout(fmt.Sprintf("HttpSpend Error: %v\n", err))
		return nil
	}
	tss.Stdout(result)
	return nil
}

func handleNostrKeygen(args []string) error {
	if len(args) < 8 || len(args) > 10 {
		tss.Stderr("Usage: nostr-keygen <relay> <nsec> <npub> <npubs> <ppm> <session_id> <session_key> <chaincode> <save: write keyshare file to current dir> <passphare: aes encrypt keyshare file> <verbose default blank>")
		return nil
	}
	nostrRelay := args[0]
	localNsec := args[1]
	localNpub := args[2]
	partyNpubs := args[3]
	ppm := args[4]
	sessionID := args[5]
	sessionKey := args[6]
	chainCode := args[7]
	save := ""
	passphrase := ""
	if len(args) > 8 {
		save = args[8]
	}
	if len(args) > 9 {
		passphrase = args[9]
	}
	v := "false"
	if globalVerbose {
		v = "true"
	}
	result, err := tss.NostrKeygen(nostrRelay, localNsec, localNpub, partyNpubs, ppm, sessionID, sessionKey, chainCode, v)
	if err != nil {
		tss.Logf("Go Error: %v\n", err)
		return nil
	}
	var localState tss.LocalState
	if err := json.Unmarshal([]byte(result), &localState); err != nil {
		tss.Stderr(fmt.Sprintf("Failed to parse keyshare for %s: %v\n", localNpub, err))
		return nil
	}
	updatedKeyshare, err := json.Marshal(localState)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to marshal keyshare for %s: %v\n", localNpub, err))
		return nil
	}
	tss.Logf("%s Keygen Result Saved\n", localNpub)
	content := result
	switch save {
	case "base64":
		content = base64.StdEncoding.EncodeToString(updatedKeyshare)
		tss.Stdout(content)
	case "save":
		keyshareFile := localNpub + ".ks"
		if len(passphrase) > 0 {
			hashPass, _ := tss.Sha256(passphrase)
			content, _ = tss.AesEncrypt(content, hashPass)
		}
		if err := os.WriteFile(keyshareFile, []byte(content), 0644); err != nil {
			fmt.Printf("Failed to save keyshare for %s: %v\n", localNpub, err)
			return nil
		}
		tss.Stdout("saved: " + keyshareFile)
	default:
		tss.Stdout(result)
	}
	return nil
}

func handleNostrKeysign(args []string) error {
	if len(args) < 10 {
		return fmt.Errorf("usage: nostr-keysign <relay> <nsec> <npub> <npubs> <keyshare> <sessionID> <sessionKey> <message> <derivePath> <passphrase>")
	}
	nostrRelay := args[0]
	localNsec := args[1]
	localNpub := args[2]
	partyNpubs := args[3]
	keyshare := args[4]
	sessionID := args[5]
	sessionKey := args[6]
	message := args[7]
	derivePath := args[8]
	passphrase := args[9]
	if len(passphrase) > 0 {
		tss.Logln("Decrypting keyshare")
		hashpass, _ := tss.Sha256(passphrase)
		keyshare, _ = tss.AesDecrypt(keyshare, hashpass)
	}
	v := "false"
	if globalVerbose {
		v = "true"
	}
	result, err := tss.NostrKeysign(nostrRelay, localNpub, localNsec, partyNpubs, keyshare, sessionID, sessionKey, message, derivePath, v)
	if err != nil {
		tss.Stdout(fmt.Sprintf("NostrKeysign Error: %v\n", err))
		return nil
	}
	tss.Stdout(result)
	return nil
}

func handleNostrSpend(args []string) error {
	if len(args) < 12 {
		return fmt.Errorf("usage: nostr-spend <relay> <nsec> <npub> <npubs> <sessionID> <sessionKey> <senderAddress> <receiverAddress> <derivePath> <amountSatoshi> <estimatedFee> <keyshare> [passphrase]")
	}
	nostrRelay := args[0]
	localNsec := args[1]
	localNpub := args[2]
	partyNpubs := args[3]
	sessionID := args[4]
	sessionKey := args[5]
	senderAddress := args[6]
	receiverAddress := args[7]
	derivePath := args[8]
	amountSatoshi, err := strconv.ParseInt(args[9], 10, 64)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Invalid amountSatoshi: %v\n", err))
		return nil
	}
	estimatedFee, err := strconv.ParseInt(args[10], 10, 64)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Invalid estimatedFee: %v\n", err))
		return nil
	}
	keyshare := args[11]
	passphrase := ""
	if len(args) > 12 {
		passphrase = args[12]
	}
	if len(passphrase) > 0 {
		tss.Logln("Decrypting keyshare")
		hashpass, err := tss.Sha256(passphrase)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to hash: %v\n", err))
			return nil
		}
		keyshare, err = tss.AesDecrypt(keyshare, hashpass)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to AesDecrypt: %v\n", err))
			return nil
		}
		tss.Logln("Decrypted Keyshare:" + keyshare)
	} else {
		decodedKeyshare, err := base64.StdEncoding.DecodeString(keyshare)
		if err != nil {
			tss.Stderr(fmt.Sprintf("Failed to decode base64 keyshare: %v\n", err))
			return nil
		}
		keyshare = string(decodedKeyshare)
	}

	var localState tss.LocalState
	if err := json.Unmarshal(([]byte(keyshare)), &localState); err != nil {
		tss.Stderr(fmt.Sprintf("Failed to parse keyshare: %v\n", err))
		return nil
	}
	btcPub, err := tss.GetDerivedPubKey(localState.PubKey, localState.ChainCodeHex, derivePath, false)
	if err != nil {
		tss.Stderr(fmt.Sprintf("Failed to get derived public key: %v\n", err))
		return nil
	}
	v := "false"
	if globalVerbose {
		v = "true"
	}
	result, err := tss.MpcSendBTC(
		nostrRelay, localNpub, partyNpubs, sessionID, sessionKey, localNsec, v,
		keyshare, derivePath, btcPub,
		senderAddress, receiverAddress, amountSatoshi, estimatedFee,
		"nostr",
	)
	if err != nil {
		tss.Stdout(fmt.Sprintf("NostrSpend Error: %v\n", err))
		return nil
	}
	tss.Stdout(result)
	return nil
}

func main() {
	cli := NewCLI()

	// Register all commands
	cli.RegisterCommand(Command{
		Name:        "ecies-keypair",
		Description: "Generate ECIES key pair",
		Handler:     handleEciesKeypair,
	})

	cli.RegisterCommand(Command{
		Name:        "ecies-encrypt",
		Description: "Encrypt data using ECIES",
		Usage:       "ecies-encrypt <data> <publicKey>",
		Handler:     handleEciesEncrypt,
	})

	cli.RegisterCommand(Command{
		Name:        "ecies-decrypt",
		Description: "Decrypt data using ECIES",
		Usage:       "ecies-decrypt <encryptedData> <privateKey>",
		Handler:     handleEciesDecrypt,
	})

	cli.RegisterCommand(Command{
		Name:        "preparams",
		Description: "Generate pre-parameters",
		Usage:       "preparams <ppm>",
		Handler:     handlePreparams,
	})

	cli.RegisterCommand(Command{
		Name:        "nostr-keypair",
		Description: "Generate Nostr key pair",
		Handler:     handleNostrKeypair,
	})

	cli.RegisterCommand(Command{
		Name:        "random-seed",
		Description: "Generate random seed",
		Usage:       "random-seed [length]",
		Handler:     handleRandomSeed,
	})

	cli.RegisterCommand(Command{
		Name:        "derive-address",
		Description: "Derive Bitcoin address",
		Usage:       "derive-address <network> <type> <xpub> <chaincode> [path]",
		Handler:     handleDeriveAddress,
	})

	cli.RegisterCommand(Command{
		Name:        "http-relay",
		Description: "Start HTTP relay server",
		Usage:       "http-relay <port>",
		Handler:     handleHttpRelay,
	})

	cli.RegisterCommand(Command{
		Name:        "http-keygen",
		Description: "MPC-TSS over HTTP Relay - Keygen",
		Usage:       "http-keygen <server> <session> <chainCode> <party> <parties> <encKey> <decKey> <sessionKey> <ppm> [save] [passphrase]",
		Handler:     handleHttpKeygen,
	})

	cli.RegisterCommand(Command{
		Name:        "http-keysign",
		Description: "MPC-TSS over HTTP Relay - Keysign",
		Usage:       "http-keysign <server> <session> <party> <parties> <encKey> <decKey> <keyshare> <derivePath> <message> <sessionKey> <passphrase>",
		Handler:     handleHttpKeysign,
	})

	cli.RegisterCommand(Command{
		Name:        "http-spend",
		Description: "MPC-TSS over HTTP Relay - Bitcoin Transaction",
		Usage:       "http-spend <server> <session> <party> <parties> <encKey> <decKey> <sessionKey> <senderAddress> <receiverAddress> <derivePath> <amountSatoshi> <estimatedFee> <keyshare> [passphrase]",
		Handler:     handleHttpSpend,
	})

	cli.RegisterCommand(Command{
		Name:        "nostr-keygen",
		Description: "MPC-TSS over Nostr - Keygen",
		Usage:       "nostr-keygen <relay> <nsec> <npub> <npubs> <ppm> <session_id> <session_key> <chaincode> [save] [passphrase]",
		Handler:     handleNostrKeygen,
	})

	cli.RegisterCommand(Command{
		Name:        "nostr-keysign",
		Description: "MPC-TSS over Nostr - Keysign",
		Usage:       "nostr-keysign <relay> <nsec> <npub> <npubs> <keyshare> <sessionID> <sessionKey> <message> <derivePath> <passphrase>",
		Handler:     handleNostrKeysign,
	})

	cli.RegisterCommand(Command{
		Name:        "nostr-spend",
		Description: "MPC-TSS over Nostr - Bitcoin Transaction",
		Usage:       "nostr-spend <relay> <nsec> <npub> <npubs> <sessionID> <sessionKey> <senderAddress> <receiverAddress> <derivePath> <amountSatoshi> <estimatedFee> <keyshare> [passphrase]",
		Handler:     handleNostrSpend,
	})

	// Help command
	cli.RegisterCommand(Command{
		Name:        "help",
		Description: "Show detailed help and notes",
		Usage:       "help [command]",
		Handler:     handleHelp,
	})

	currentCLI = cli

	if err := cli.Execute(os.Args); err != nil {
		tss.Stderr(fmt.Sprintf("Error: %v\n", err))
		os.Exit(1)
	}
}

// handleHelp prints extended help, optional per-command usage, and global notes
func handleHelp(args []string) error {

	tss.EnableLogs()

	useColor := supportsColor()
	bold := func(s string) string {
		if useColor {
			return "\033[1m" + s + "\033[0m"
		}
		return s
	}
	green := func(s string) string {
		if useColor {
			return "\033[32m" + s + "\033[0m"
		}
		return s
	}
	dim := func(s string) string {
		if useColor {
			return "\033[2m" + s + "\033[0m"
		}
		return s
	}

	if len(args) == 1 && currentCLI != nil {
		name := args[0]
		if cmd, ok := currentCLI.commands[name]; ok {
			fmt.Printf("%s %s\n", green(cmd.Name), cmd.Description)
			if cmd.Usage != "" {
				fmt.Printf("  %s: %s\n", dim("Usage"), cmd.Usage)
			}
			return nil
		}
		return fmt.Errorf("unknown command: %s", name)
	}

	// Show grouped help then notes
	if currentCLI != nil {
		currentCLI.ShowHelp()
		fmt.Println()
	}
	// Show notes
	fmt.Println(bold("Notes:"))
	fmt.Printf("  - %s\n", "append the 'verbose' flag at the end of any command to enable logs")
	fmt.Printf("  - %s\n", "if 'passphrase' is provided, it is used to (AES) decrypt/encrypt keyshares")
	fmt.Printf("  - %s\n", "if 'save' is provided, output files are saved to the current CLI directory")
	fmt.Printf("  - %s\n", "http-spend and nostr-spend create, co-sign and broadcast a Bitcoin transaction")
	fmt.Printf("  - %s: %s\n", "website", "https://boldbitcoinwallet.com")
	fmt.Printf("  - %s\n", "TSS Messages communication is secured by AES (sessionKey) everywhere")

	return nil
}
