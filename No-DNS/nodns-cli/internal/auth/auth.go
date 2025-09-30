package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/skip2/go-qrcode"
)

type AuthConfig struct {
	PrivateKey string    `json:"private_key,omitempty"`
	PublicKey  string    `json:"public_key"`
	NPub       string    `json:"npub"`
	Method     string    `json:"method"` // "nsec", "amber", "bunker", "generated"
	BunkerURL  string    `json:"bunker_url,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

const configFileName = ".nodns-cli-auth"

func getConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, configFileName), nil
}

func saveConfig(config *AuthConfig) error {
	configPath, err := getConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(configPath, data, 0600)
}

func loadConfig() (*AuthConfig, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to get config path: %w", err)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not logged in")
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config AuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

func GenerateNewKey() error {
	// Generate 32 random bytes for private key
	privateKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privateKeyBytes); err != nil {
		return fmt.Errorf("failed to generate random bytes: %w", err)
	}

	privateKeyHex := hex.EncodeToString(privateKeyBytes)
	publicKey, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	npub, err := nip19.EncodePublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	nsec, err := nip19.EncodePrivateKey(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	config := &AuthConfig{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKey,
		NPub:       npub,
		Method:     "generated",
		CreatedAt:  time.Now(),
	}

	if err := saveConfig(config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Generated new key pair:\n")
	fmt.Printf("Public Key (npub): %s\n", npub)
	fmt.Printf("Private Key (nsec): %s\n", nsec)
	fmt.Printf("\n⚠️  IMPORTANT: Save your private key (nsec) securely!\n")
	fmt.Printf("This is the only time it will be displayed in full.\n")
	fmt.Printf("Your domain will be: %s.nostr\n", npub)

	return nil
}

func ValidateNsecKey(nsecKey string) error {
	nsecKey = strings.TrimSpace(nsecKey)

	// Try to decode as bech32 nsec
	if strings.HasPrefix(nsecKey, "nsec1") {
		_, _, err := nip19.Decode(nsecKey)
		return err
	}

	// Try as hex
	if len(nsecKey) == 64 {
		_, err := hex.DecodeString(nsecKey)
		return err
	}

	return fmt.Errorf("invalid nsec format (expected bech32 nsec1... or 64-char hex)")
}

func LoginWithNsec(nsecKey string) error {
	nsecKey = strings.TrimSpace(nsecKey)

	var privateKeyHex string
	var err error

	// Decode nsec key
	if strings.HasPrefix(nsecKey, "nsec1") {
		prefix, data, err := nip19.Decode(nsecKey)
		if err != nil {
			return fmt.Errorf("failed to decode nsec: %w", err)
		}
		if prefix != "nsec" {
			return fmt.Errorf("invalid nsec prefix")
		}

		switch v := data.(type) {
		case []byte:
			privateKeyHex = hex.EncodeToString(v)
		case string:
			privateKeyHex = v
		default:
			return fmt.Errorf("unexpected nsec data type: %T", data)
		}
	} else if len(nsecKey) == 64 {
		// Validate hex
		if _, err := hex.DecodeString(nsecKey); err != nil {
			return fmt.Errorf("invalid hex private key: %w", err)
		}
		privateKeyHex = nsecKey
	} else {
		return fmt.Errorf("invalid nsec format")
	}

	publicKey, err := nostr.GetPublicKey(privateKeyHex)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	npub, err := nip19.EncodePublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	config := &AuthConfig{
		PrivateKey: privateKeyHex,
		PublicKey:  publicKey,
		NPub:       npub,
		Method:     "nsec",
		CreatedAt:  time.Now(),
	}

	if err := saveConfig(config); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Successfully logged in!\n")
	fmt.Printf("Public Key: %s\n", npub)
	fmt.Printf("Your domain: %s.nostr\n", npub)

	return nil
}

func LoginWithAmber() error {
	// Generate a connection request for Amber
	connectURL := generateAmberConnectURL()

	fmt.Println("Scan this QR code with your Amber app:")
	qr, err := qrcode.New(connectURL, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	fmt.Println(qr.ToString(false))
	fmt.Printf("\nOr open this URL in Amber: %s\n", connectURL)

	// TODO: Implement actual Amber protocol handling
	// For now, this is a placeholder
	fmt.Println("\n⚠️  Amber integration coming soon!")
	fmt.Println("Please use 'login nsec' for now.")

	return fmt.Errorf("amber login not yet implemented")
}

func generateAmberConnectURL() string {
	// Generate a basic nostrconnect URL
	// In a real implementation, this would follow NIP-46
	return "nostrconnect://connect?relay=wss://relay.damus.io&metadata={\"name\":\"nodns-cli\",\"description\":\"Nostr DNS CLI Tool\"}"
}

func ValidateBunkerURL(bunkerURL string) error {
	bunkerURL = strings.TrimSpace(bunkerURL)

	if !strings.HasPrefix(bunkerURL, "bunker://") && !strings.HasPrefix(bunkerURL, "nostrconnect://") {
		return fmt.Errorf("bunker URL must start with bunker:// or nostrconnect://")
	}

	return nil
}

func LoginWithBunker(bunkerURL string) error {
	if err := ValidateBunkerURL(bunkerURL); err != nil {
		return err
	}

	// TODO: Implement actual bunker/NIP-46 protocol
	// For now, this is a placeholder
	fmt.Println("⚠️  Bunker login not yet implemented!")
	fmt.Println("Please use 'login nsec' for now.")

	return fmt.Errorf("bunker login not yet implemented")
}

func GetLoginStatus() (string, error) {
	config, err := loadConfig()
	if err != nil {
		return "", err
	}

	status := fmt.Sprintf(`Login Status:
  Method: %s
  Public Key: %s
  Domain: %s.nostr
  Logged in: %s`,
		config.Method,
		config.NPub,
		config.NPub,
		config.CreatedAt.Format("2006-01-02 15:04:05"))

	return status, nil
}

func Logout() error {
	configPath, err := getConfigPath()
	if err != nil {
		return fmt.Errorf("failed to get config path: %w", err)
	}

	if err := os.Remove(configPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not currently logged in")
		}
		return fmt.Errorf("failed to remove config: %w", err)
	}

	return nil
}

// GetCurrentUser returns the current logged-in user's config
func GetCurrentUser() (*AuthConfig, error) {
	return loadConfig()
}

// IsLoggedIn checks if user is currently logged in
func IsLoggedIn() bool {
	_, err := loadConfig()
	return err == nil
}
