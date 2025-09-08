# BBMTLib

**Bold Bitcoin MPC TSS Library**

A secure Multi-Party Computation (MPC) Threshold Signature Scheme (TSS) library for Bitcoin, built for mobile integration on both iOS and Android.

## How to Build

```bash
# Get dependencies
go mod tidy

# Initialize Go Mobile
go get golang.org/x/mobile/bind

# Set build flags
export GOFLAGS="-mod=mod"
```

## iOS

```bash
# Build for iOS, macOS, and iOS Simulator
gomobile bind -v -target=ios,macos,iossimulator -tags=ios,macos,iossimulator github.com/BoldBitcoinWallet/BBMTLib/tss
```

## Android

```bash
# Build for Android
gomobile bind -v -target=android github.com/BoldBitcoinWallet/BBMTLib/tss

# If the following error occurs  
"no usable NDK in /Android/Sdk: unsupported API version 16"
# Then specify the version api with the following command
gomobile bind -v -target=android -androidapi 21 github.com/BoldBitcoinWallet/BBMTLib/tss
```


## MPC TSS Transaction Over Nostr Diagram

- All Nostr messages are encrypted using the NIP-44 standard for this design.

- It is recommended to self host a Nostr Relay for added privacy
(https://github.com/scsibug/nostr-rs-relay)

- If a self-hosted nostr relay is not possible, choose a Relay with a high rate limit. https://nostr.info/relays/

- (Average of 30 nostr messages are sent/recieved within 20 seconds, for each UTXO)

- Wallet User(s) should mutually share Nostr nPubs and Nostr Relay URL for later communication protocol over NOSTR to create a multiparty wallet. 

- It's recommended that sharing the Nostr Pubkeys be done privately in person or via external messaging (Signal, ProtonMail, ect)

![Nostr Diagram](Nostr_Diagram.png)


## License  
This project is licensed under the **Apache-2.0 License**. See [LICENSE](LICENSE) for details.  

## NOTICE  
This product includes modified code from third-party projects. For full attribution details, see the [NOTICE](NOTICE) file.  