package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the server configuration
type Config struct {
	Port         int           `yaml:"port"`
	Relays       []string      `yaml:"relays"`
	ForwardDNS   []string      `yaml:"forward_dns"`
	TTL          uint32        `yaml:"ttl"`
	Certificates CertConfig    `yaml:"certificates"`
	Logging      LoggingConfig `yaml:"logging"`
}

// CertConfig contains certificate-related settings
type CertConfig struct {
	AutoInstall      bool     `yaml:"auto_install"`      // DANGEROUS: Auto-install without prompting
	PromptUser       bool     `yaml:"prompt_user"`       // Prompt before each installation
	NonInteractive   bool     `yaml:"non_interactive"`   // Avoid fingerprint/Touch ID prompts
	RequiredTLDs     []string `yaml:"required_tlds"`     // Only install certs for these TLDs
	SkipExpired      bool     `yaml:"skip_expired"`      // Skip expired certificates
	SkipSelfSigned   bool     `yaml:"skip_self_signed"`  // Skip self-signed certificates
	MaxAge           int      `yaml:"max_age_days"`      // Skip certs older than X days
	AuditLog         string   `yaml:"audit_log"`         // Path to audit log file
	DisableDangerous bool     `yaml:"disable_dangerous"` // Completely disable cert installation
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level    string `yaml:"level"`     // debug, info, warn, error
	Format   string `yaml:"format"`    // json, text
	AuditLog string `yaml:"audit_log"` // Path to audit log file
}

// DefaultConfig returns a safe default configuration
func DefaultConfig() *Config {
	return &Config{
		Port: 5354,
		Relays: []string{
			"wss://relay.damus.io",
			"wss://nos.lol",
			"wss://relay.snort.social",
			"wss://relay.nostr.band",
			"wss://nostr.wine",
		},
		ForwardDNS: []string{"1.1.1.1", "1.0.0.1"},
		TTL:        3600,
		Certificates: CertConfig{
			AutoInstall:      false,      // NEVER enable by default
			PromptUser:       true,       // Always prompt
			NonInteractive:   false,      // Allow Touch ID prompts by default
			RequiredTLDs:     []string{}, // Empty = all TLDs
			SkipExpired:      true,
			SkipSelfSigned:   true, // Skip self-signed for safety
			MaxAge:           365,  // Only install recent certificates
			AuditLog:         "",   // No audit log by default
			DisableDangerous: true, // Disable dangerous features by default
		},
		Logging: LoggingConfig{
			Level:    "info",
			Format:   "text",
			AuditLog: "",
		},
	}
}

// Load loads configuration from file or returns defaults
func Load(configPath string) (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// If no config path specified, try to find config.yaml
	if configPath == "" {
		candidates := []string{
			"config.yaml",
			"nodns-server.yaml",
			"/etc/nodns-server/config.yaml",
			filepath.Join(os.Getenv("HOME"), ".config", "nodns-server", "config.yaml"),
		}

		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				configPath = candidate
				break
			}
		}
	}

	// If still no config file, use defaults
	if configPath == "" {
		fmt.Println("No configuration file found, using defaults")
		return cfg, nil
	}

	// Load and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	fmt.Printf("Loaded configuration from %s\n", configPath)
	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", c.Port)
	}

	if len(c.Relays) == 0 {
		return fmt.Errorf("at least one Nostr relay must be configured")
	}

	if len(c.ForwardDNS) == 0 {
		return fmt.Errorf("at least one forward DNS server must be configured")
	}

	// Validate relay URLs
	for _, relay := range c.Relays {
		if relay == "" {
			return fmt.Errorf("empty relay URL found")
		}
		if !isValidRelayURL(relay) {
			return fmt.Errorf("invalid relay URL: %s", relay)
		}
	}

	// Security validation for certificate settings
	if c.Certificates.AutoInstall && !c.Certificates.DisableDangerous {
		fmt.Println("⚠️  WARNING: Certificate auto-install is enabled - this is dangerous!")
	}

	return nil
}

// Save writes the current configuration to a file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration to %s: %w", path, err)
	}

	return nil
}

// IsCertificateEnabled returns true if certificate functionality is enabled
func (c *Config) IsCertificateEnabled() bool {
	return !c.Certificates.DisableDangerous
}

// ShouldInstallCertForTLD returns true if certificates should be installed for the given TLD
func (c *Config) ShouldInstallCertForTLD(tld string) bool {
	if c.Certificates.DisableDangerous {
		return false
	}

	// If no specific TLDs configured, allow all
	if len(c.Certificates.RequiredTLDs) == 0 {
		return true
	}

	// Check if TLD is in the allowed list
	for _, allowedTLD := range c.Certificates.RequiredTLDs {
		if allowedTLD == tld {
			return true
		}
	}

	return false
}

// isValidRelayURL performs basic validation of relay URLs
func isValidRelayURL(url string) bool {
	return len(url) > 6 && (url[:6] == "wss://" || url[:5] == "ws://")
}

// GenerateExampleConfig creates an example configuration file
func GenerateExampleConfig(path string) error {
	// Add comments by creating a custom YAML structure
	yamlContent := `# nodns-server configuration
# ⚠️ SECURITY WARNING: Certificate features can be extremely dangerous

# DNS server port (requires root/admin for port 53)
port: 5354

# Nostr relays to query for DNS records and certificates
relays:
  - "wss://relay.damus.io"
  - "wss://nos.lol"
  - "wss://relay.snort.social"
  - "wss://relay.nostr.band"
  - "wss://nostr.wine"

# Forward DNS servers for non-.nostr domains
forward_dns:
  - "1.1.1.1"  # Cloudflare
  - "1.0.0.1"  # Cloudflare

# Default TTL for DNS responses (seconds)
ttl: 3600

# Certificate settings - ⚠️ EXTREMELY DANGEROUS ⚠️
certificates:
  # NEVER enable auto_install in production!
  auto_install: false
  
  # Always prompt users before installing certificates
  prompt_user: true
  
  # Only install certificates for these TLDs (empty = all TLDs)
  required_tlds: []
  
  # Skip expired certificates
  skip_expired: true
  
  # Skip self-signed certificates (recommended for security)
  skip_self_signed: true
  
  # Skip certificates older than this many days
  max_age_days: 365
  
  # Path to certificate audit log file
  audit_log: ""
  
  # RECOMMENDED: Completely disable certificate functionality
  disable_dangerous: true

# Logging configuration
logging:
  level: "info"     # debug, info, warn, error
  format: "text"    # text, json
  audit_log: ""     # Path to audit log file
`

	return os.WriteFile(path, []byte(yamlContent), 0644)
}
