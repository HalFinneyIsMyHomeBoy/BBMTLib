//go:build js && wasm
// +build js,wasm

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall/js"

	tss "github.com/BoldBitcoinWallet/BBMTLib/tss"

	eciesgo "github.com/ecies/go/v2"
)

// ECIES Utility Functions
func GenerateKeyPair() (string, error) {
	privKey, err := eciesgo.GenerateKey()
	if err != nil {
		return "", err
	}
	pubKey := privKey.PublicKey
	keyPair := map[string]string{
		"privateKey": privKey.Hex(),
		"publicKey":  pubKey.Hex(true),
	}
	keyPairJSON, err := json.Marshal(keyPair)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key pair to JSON: %w", err)
	}
	return string(keyPairJSON), nil
}

func EciesEncrypt(data, publicKeyHex string) (string, error) {
	publicKey, err := eciesgo.NewPublicKeyFromHex(publicKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	encryptedData, err := eciesgo.Encrypt(publicKey, []byte(data))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}
	encodedData := base64.StdEncoding.EncodeToString(encryptedData)
	return encodedData, nil
}

func EciesDecrypt(encryptedData, privateKeyHex string) (string, error) {
	privateKey, err := eciesgo.NewPrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode private key: %w", err)
	}
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %w", err)
	}
	decryptedData, err := eciesgo.Decrypt(privateKey, encryptedBytes)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}
	return string(decryptedData), nil
}

// Wrapper functions for JavaScript interop
func generateKeyPairJS(this js.Value, args []js.Value) interface{} {
	keypair, err := GenerateKeyPair()
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}
	return keypair
}

func encryptJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf(map[string]string{"error": "invalid number of arguments"})
	}
	data := args[0].String()
	publicKeyHex := args[1].String()
	encrypted, err := EciesEncrypt(data, publicKeyHex)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	return js.ValueOf(map[string]interface{}{"data": encrypted})
}

func decryptJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return js.ValueOf(map[string]string{"error": "invalid number of arguments"})
	}
	encryptedData := args[0].String()
	privateKeyHex := args[1].String()
	decrypted, err := EciesDecrypt(encryptedData, privateKeyHex)
	if err != nil {
		return js.ValueOf(map[string]interface{}{"error": err.Error()})
	}

	return js.ValueOf(map[string]interface{}{"data": decrypted})
}

func getContentJS(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return js.ValueOf(map[string]string{"error": "invalid number of arguments"})
	}
	url := args[0].String()

	// Use JavaScript's fetch API to make the HTTP request
	promise := js.Global().Call("fetch", url).Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		response := args[0]
		return response.Call("text")
	})).Call("then", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		text := args[0].String()
		return js.ValueOf(map[string]interface{}{"data": text})
	})).Call("catch", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		err := args[0].String()
		return js.ValueOf(map[string]interface{}{"error": err})
	}))

	return promise
}

func preParamsJS(this js.Value, args []js.Value) interface{} {
	// 1. Create the Promise executor function.
	// This function receives `resolve` and `reject` callbacks from JavaScript.
	handler := js.FuncOf(func(this js.Value, pArgs []js.Value) interface{} {
		resolve := pArgs[0]
		reject := pArgs[1]

		// 2. Run the actual logic in a new goroutine to avoid blocking.
		go func() {
			// 3. IMPORTANT: Release the js.Func to avoid memory leaks.
			// `defer` ensures this runs whether we resolve or reject.

			// Assuming `tss.PreParams` might also return an error for robust handling.
			preParams, err := tss.PreParams("")
			if err != nil {
				// 4a. On failure, reject the promise with a proper JS Error object.
				errorObject := js.Global().Get("Error").New(err.Error())
				reject.Invoke(errorObject)
				return
			}

			data, err := json.Marshal(preParams)
			if err != nil {
				// 4b. On JSON marshaling failure, also reject the promise.
				errorObject := js.Global().Get("Error").New(err.Error())
				reject.Invoke(errorObject)
				return
			}

			ppm := string(data)
			fmt.Println("Go (Wasm) console:", ppm) // For debugging in the browser console

			// 5. On success, resolve the promise with the final data structure.
			successObject := js.ValueOf(map[string]interface{}{
				"data": ppm,
			})
			resolve.Invoke(successObject)
		}()

		// The handler function itself returns `undefined` (represented by `nil`).
		return nil
	})
	defer handler.Release()

	// 6. Get the global JavaScript `Promise` constructor and create a new Promise.
	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

type Filter struct {
	Kinds [1]int `json:"kinds"`
	Limit int    `json:"limit"`
}

type RequestMessage struct {
	Req    string `json:"req"`
	SubID  string `json:"sub_id"`
	Filter Filter `json:"filter"`
}

// NOTE: You must have your RequestMessage and Filter structs defined somewhere.
// type RequestMessage struct { ... }
// type Filter struct { ... }

func nostrConnectRelayJS(this js.Value, args []js.Value) interface{} {
	if len(args) == 0 || args[0].Type() != js.TypeString {
		errorMsg := "Error: A WebSocket URL (string) is required."
		// In a Promise-based function, we return a rejected promise for invalid args.
		return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(errorMsg))
	}
	relayURL := args[0].String()

	// 1. The Promise constructor takes an "executor" function with (resolve, reject) arguments.
	promiseExecutor := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		// 2. Run the WebSocket connection logic in a separate goroutine.
		// This allows the executor to return and the Promise to be created immediately.
		go func() {
			ws := js.Global().Get("WebSocket").New(relayURL)

			var onOpen, onMessage, onError, onClose js.Func

			onOpen = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				fmt.Println("[Go WASM] Connected to", relayURL)
				// 3. On success, call the `resolve` function of the Promise.
				resolve.Invoke(js.ValueOf("Successfully connected to " + relayURL))

				// You can still send your subscription message here
				msg := RequestMessage{ /* ... */ }
				b, _ := json.Marshal(msg)
				ws.Call("send", string(b))
				return nil
			})

			onError = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				fmt.Println("[Go WASM] WebSocket error")
				// 3. On failure, call the `reject` function of the Promise.
				// It's standard to reject with an Error object.
				errObject := js.Global().Get("Error").New("WebSocket connection error to " + relayURL)
				reject.Invoke(errObject)
				return nil
			})

			// These handlers remain for the life of the connection
			onMessage = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				msg := args[0].Get("data").String()
				fmt.Println("[Go WASM] 📩 Received:", msg)
				return nil
			})

			onClose = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
				fmt.Println("[Go WASM] WebSocket closed")
				// Release callbacks to prevent memory leaks when connection is fully terminated
				onOpen.Release()
				onError.Release()
				onMessage.Release()
				onClose.Release()
				return nil
			})

			ws.Set("onopen", onOpen)
			ws.Set("onerror", onError)
			ws.Set("onmessage", onMessage)
			ws.Set("onclose", onClose)
		}()

		return nil // Executor function must return undefined
	})

	// 4. Create and return the new Promise object. This happens immediately.
	return js.Global().Get("Promise").New(promiseExecutor)
}

func nostrJoinKeygenJS(this js.Value, args []js.Value) interface{} {
	// --- Argument Validation ---
	if len(args) < 6 {
		errorMsg := "Error: 9 arguments are required (nostrRelay, localNsec, localNpub, partyNpubs, ppm, sessionID, sessionKey, chainCode, verbose)."
		// Return a promise that is already rejected
		return js.Global().Get("Promise").Call("reject", js.Global().Get("Error").New(errorMsg))
	}

	// 1. Define the executor function that contains the core logic.
	promiseExecutor := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		// 2. Launch a goroutine to do the work in the background.
		go func() {
			// Parse arguments inside the goroutine
			nostrRelay := args[0].String()
			localNsec := args[1].String()
			localNpub := args[2].String()
			partyNpubs := args[3].String()
			ppm := args[4].String()
			sessionID := args[5].String()
			sessionKey := args[6].String()
			chainCode := args[7].String()
			verbose := args[8].String()
			// Call your potentially long-running function
			result, err := tss.NostrKeygen(nostrRelay, localNsec, localNpub, partyNpubs, ppm, sessionID, sessionKey, chainCode, verbose)

			// 3. Resolve or reject the promise based on the outcome.
			if err != nil {
				// On error, reject the promise with a new JavaScript Error object.
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}

			// On success, resolve the promise with the result.
			resolve.Invoke(js.ValueOf(map[string]interface{}{"data": result}))
		}()

		return nil // The executor must return `undefined`.
	})

	// 4. Create and return the new Promise. This happens instantly.
	return js.Global().Get("Promise").New(promiseExecutor)
}

func httpJoinKeygenJS(this js.Value, args []js.Value) interface{} {

	// 1. Define the executor function that contains the core logic.
	promiseExecutor := js.FuncOf(func(this js.Value, promiseArgs []js.Value) interface{} {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		// 2. Launch a goroutine to do the work in the background.
		go func() {
			// Parse arguments inside the goroutine
			server := args[0].String()
			session := args[1].String()
			chainCode := args[2].String()
			party := args[3].String()
			parties := args[4].String()
			encKey := ""
			decKey := ""
			sessionKey := args[5].String()
			ppm := args[6].String()
			net_type := "http"

			//join keygen
			result, err := tss.JoinKeygen(ppm, party, parties, encKey, decKey, session, server, chainCode, sessionKey, net_type)

			// 3. Resolve or reject the promise based on the outcome.
			if err != nil {
				// On error, reject the promise with a new JavaScript Error object.
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}

			// On success, resolve the promise with the result.
			resolve.Invoke(js.ValueOf(map[string]interface{}{"data": result}))
		}()

		return nil // The executor must return `undefined`.
	})

	// 4. Create and return the new Promise. This happens instantly.
	return js.Global().Get("Promise").New(promiseExecutor)

}

func main() {
	js.Global().Set("generateKeyPair", js.FuncOf(generateKeyPairJS))
	js.Global().Set("eciesEncrypt", js.FuncOf(encryptJS))
	js.Global().Set("eciesDecrypt", js.FuncOf(decryptJS))
	js.Global().Set("getContent", js.FuncOf(getContentJS))

	js.Global().Set("nostrJoinKeygen", js.FuncOf(nostrJoinKeygenJS))
	js.Global().Set("preParams", js.FuncOf(preParamsJS))

	js.Global().Set("nostrConnectRelay", js.FuncOf(nostrConnectRelayJS))

	js.Global().Set("httpJoinKeygen", js.FuncOf(httpJoinKeygenJS))

	<-make(chan struct{})
}
