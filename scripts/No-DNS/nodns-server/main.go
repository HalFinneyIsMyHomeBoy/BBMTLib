package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/nostr-dns/nodns-server/internal/config"
	"github.com/nostr-dns/nodns-server/internal/dns"
	"github.com/nostr-dns/nodns-server/internal/nostr"
	"github.com/sirupsen/logrus"
)

func main() {
	// Command line flags
	var (
		configPath         = flag.String("config", "", "Path to configuration file")
		port               = flag.Int("port", 0, "DNS server port (overrides config)")
		certAuto           = flag.Bool("cert-auto-install", false, "⚠️ DANGER: Auto-install certificates without prompting")
		certNonInteractive = flag.Bool("cert-non-interactive", false, "Avoid fingerprint/Touch ID prompts during certificate installation")
		certDisable        = flag.Bool("cert-disable", false, "Completely disable certificate functionality (recommended)")
		verbose            = flag.Bool("verbose", false, "Enable verbose logging")
		help               = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Configure logging
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Show security warning for dangerous certificate features
	if *certAuto {
		showSecurityWarning()
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.Fatalf("Failed to load configuration: %v", err)
	}

	// Override config with command line flags
	if *port != 0 {
		cfg.Port = *port
	}
	if *certAuto {
		cfg.Certificates.AutoInstall = true
		cfg.Certificates.DisableDangerous = false
	}
	if *certNonInteractive {
		cfg.Certificates.NonInteractive = true
		logrus.Info("SECURITY INFO: Certificate non-interactive mode enabled (no fingerprint prompts)")
	}
	if *certDisable {
		cfg.Certificates.DisableDangerous = true
	}

	// Create Nostr client
	nostrClient := nostr.NewClient(cfg.Relays)
	defer nostrClient.Close()

	// Create DNS server
	dnsServer, err := dns.NewServer(cfg, nostrClient)
	if err != nil {
		logrus.Fatalf("Failed to create DNS server: %v", err)
	}

	// Start server
	logrus.Infof("Starting nodns-server on port %d", cfg.Port)
	logrus.Infof("Using %d Nostr relays", len(cfg.Relays))
	logrus.Infof("Forward DNS: %v", cfg.ForwardDNS)

	if cfg.Certificates.DisableDangerous {
		logrus.Info("✅ Certificate functionality DISABLED (safe mode)")
	} else {
		logrus.Warn("⚠️  Certificate functionality ENABLED (dangerous)")
		if cfg.Certificates.AutoInstall {
			logrus.Error("🚨 AUTO-INSTALL enabled - EXTREMELY DANGEROUS")
		}
	}

	if err := dnsServer.Start(); err != nil {
		logrus.Fatalf("Failed to start DNS server: %v", err)
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logrus.Info("DNS server started. Press Ctrl+C to stop.")
	<-sigChan

	logrus.Info("Shutting down...")
	dnsServer.Stop()
}

func showHelp() {
	fmt.Println(`nodns-server - DNS server for .nostr domains

⚠️  SECURITY WARNING ⚠️
This software can automatically install certificates to your system's trust store.
This is EXTREMELY DANGEROUS and should only be used in isolated testing environments.

Usage:
  nodns-server [options]

Options:
  -config string
        Path to configuration file (default: searches for config.yaml)
  -port int
        DNS server port (overrides config, default: 5354)
  -cert-disable
        Completely disable certificate functionality (RECOMMENDED)
  -cert-auto-install
        ⚠️ DANGER: Auto-install certificates without prompting
  -verbose
        Enable verbose logging
  -help
        Show this help message

Examples:
  # Safe mode (certificates disabled)
  sudo ./nodns-server -cert-disable

  # Development mode (prompts for certificates)  
  sudo ./nodns-server -port 5354

  # ⚠️ DANGEROUS: Auto-install certificates
  sudo ./nodns-server -cert-auto-install

Configuration:
  Place config.yaml in current directory or specify with -config flag.
  See README.md for configuration options.

Security:
  - Run in isolated VMs only
  - Never use on production systems
  - Always use -cert-disable in production
  - Understand PKI/certificate risks before enabling certificate features
`)
}

func showSecurityWarning() {
	fmt.Print(`
🚨🚨🚨 CRITICAL SECURITY WARNING 🚨🚨🚨

You have enabled automatic certificate installation!

This is EXTREMELY DANGEROUS and can:
- Compromise your entire system's security
- Allow man-in-the-middle attacks
- Enable traffic interception
- Break TLS/SSL protection system-wide

ARE YOU SURE you want to continue? This should ONLY be used
in isolated testing environments!

Type 'I UNDERSTAND THE RISKS' to continue: `)

	var response string
	fmt.Scanln(&response)

	if response != "I UNDERSTAND THE RISKS" {
		fmt.Println("Aborting for safety.")
		os.Exit(1)
	}

	fmt.Println("⚠️ Proceeding with dangerous certificate auto-installation enabled.")
	fmt.Println("⚠️ Monitor logs carefully for certificate installation events.")
}
