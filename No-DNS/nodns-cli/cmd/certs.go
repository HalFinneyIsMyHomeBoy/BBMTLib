package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/nostr-dns/nodns-cli/internal/auth"
	"github.com/nostr-dns/nodns-cli/internal/certs"
	"github.com/spf13/cobra"
)

// certsCmd represents the certs command
var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Manage SSL certificates",
	Long:  `Manage SSL certificates published to Nostr`,
	Run: func(cmd *cobra.Command, args []string) {
		showCertsMenu()
	},
}

var listCertsCmd = &cobra.Command{
	Use:   "list",
	Short: "List current certificates",
	Long:  `Display all certificates for your domain`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		if err := certs.ListCurrentCertificates(); err != nil {
			fmt.Fprintf(os.Stderr, "Error listing certificates: %v\n", err)
			os.Exit(1)
		}
	},
}

var addCertCmd = &cobra.Command{
	Use:   "add [tld] [cert_file]",
	Short: "Add a certificate",
	Long:  `Add a certificate for a specific TLD by pasting or loading from file`,
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var tld, certFile string
		var err error

		if len(args) >= 1 {
			tld = args[0]
		} else {
			tld, err = promptForTLD()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		if len(args) >= 2 {
			certFile = args[1]
			// Read certificate from file and publish to Nostr
			data, err := os.ReadFile(certFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
				os.Exit(1)
			}
			if err := certs.PublishCertificate(tld, string(data), false); err != nil {
				fmt.Fprintf(os.Stderr, "Error publishing certificate: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Println("Interactive certificate pasting not yet implemented")
			fmt.Println("Please provide a certificate file path")
			os.Exit(1)
		}

		fmt.Printf("Successfully added and published certificate for .%s\n", tld)
	},
}

var generateCertCmd = &cobra.Command{
	Use:   "generate [tld]",
	Short: "Generate a self-signed certificate",
	Long:  `Generate a self-signed certificate for the specified TLD(s)`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var tlds []string
		var err error

		if len(args) >= 1 {
			// Single TLD specified
			tlds = []string{args[0]}
		} else {
			// Interactive selection
			tlds, err = promptForMultipleTLDs()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Get output directory from flag or prompt
		var outputDir string
		if cmd != nil && cmd.Flags() != nil {
			outputDir, _ = cmd.Flags().GetString("output")
		}
		if outputDir == "" {
			var err error
			outputDir, err = promptForOutputDirectory()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		for _, tld := range tlds {
			if err := certs.GenerateAndPublishCertificate(tld, outputDir); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating certificate for .%s: %v\n", tld, err)
				continue
			}
		}
	},
}

var removeCertCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a certificate",
	Long:  `Remove an existing certificate`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		// Interactive removal - fetch and select from Nostr
		certificates, err := certs.FetchCurrentCertificates()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching certificates: %v\n", err)
			os.Exit(1)
		}

		if len(certificates) == 0 {
			fmt.Println("No certificates to remove.")
			return
		}

		// Create display items
		items := make([]string, len(certificates))
		for i, cert := range certificates {
			items[i] = fmt.Sprintf(".%s - %s", cert.TLD, cert.Subject)
		}

		prompt := promptui.Select{
			Label: "Select certificate to remove",
			Items: items,
		}

		index, _, err := prompt.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		selectedCert := certificates[index]
		if err := certs.RemoveCertificate(selectedCert.TLD); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing certificate: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Successfully removed certificate for .%s\n", selectedCert.TLD)
	},
}

var publishCertsCmd = &cobra.Command{
	Use:   "publish [tld]",
	Short: "Publish certificates to Nostr",
	Long:  `Publish certificates to Nostr relays. If TLD is specified, publish only that certificate.`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		fmt.Println("Publish command not needed - certificates are automatically published when generated or added")
		fmt.Println("Use 'nodns certs list' to see published certificates")
	},
}

var showCertCmd = &cobra.Command{
	Use:   "show [tld]",
	Short: "Show certificate details",
	Long:  `Display detailed information about a certificate`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var tld string
		var err error

		if len(args) >= 1 {
			tld = args[0]
		} else {
			tld, err = promptForTLD()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Fetch certificates and show the specified one
		certificates, err := certs.FetchCurrentCertificates()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching certificates: %v\n", err)
			os.Exit(1)
		}

		var foundCert *certs.NostrCertificate
		for _, cert := range certificates {
			if cert.TLD == tld {
				foundCert = &cert
				break
			}
		}

		if foundCert == nil {
			fmt.Printf("No certificate found for .%s\n", tld)
			os.Exit(1)
		}

		user, err := auth.GetCurrentUser()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting user: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Certificate for .%s\n", foundCert.TLD)
		fmt.Println("========================")
		fmt.Printf("Domain: %s.%s\n", user.NPub, foundCert.TLD)
		fmt.Printf("Subject: %s\n", foundCert.Subject)
		fmt.Printf("Issuer: %s\n", foundCert.Issuer)
		fmt.Printf("Valid From: %s\n", foundCert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("Valid To: %s\n", foundCert.NotAfter.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("Generated by tool: %t\n", foundCert.Generated)

		// Check expiry
		if foundCert.NotAfter.Before(time.Now()) {
			fmt.Printf("\n⚠️  Certificate is EXPIRED\n")
		} else if foundCert.NotAfter.Before(time.Now().AddDate(0, 0, 30)) {
			fmt.Printf("\n⚠️  Certificate expires in less than 30 days\n")
		}

		fmt.Printf("\nPEM Certificate:\n%s\n", foundCert.PEM)
	},
}

func showCertsMenu() {
	prompt := promptui.Select{
		Label: "Certificate Management",
		Items: []string{
			"List certificates",
			"Add certificate (paste/file)",
			"Generate self-signed certificate",
			"Generate multiple certificates",
			"Show certificate details",
			"Remove certificate",
			"Publish certificates to Nostr",
			"Back to main menu",
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	switch index {
	case 0:
		listCertsCmd.Run(nil, nil)
	case 1:
		addCertCmd.Run(nil, nil)
	case 2:
		generateCertCmd.Run(nil, nil)
	case 3:
		generateMultipleCerts()
	case 4:
		showCertCmd.Run(nil, nil)
	case 5:
		removeCertCmd.Run(nil, nil)
	case 6:
		publishCertsCmd.Run(nil, nil)
	case 7:
		return
	}
}

func generateMultipleCerts() {
	prompt := promptui.Select{
		Label: "Generate certificates for which TLDs?",
		Items: []string{
			".nostr only",
			".nostr and .net",
			".nostr, .net, and .com",
			"Custom selection",
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var tlds []string
	switch index {
	case 0:
		tlds = []string{"nostr"}
	case 1:
		tlds = []string{"nostr", "net"}
	case 2:
		tlds = []string{"nostr", "net", "com"}
	case 3:
		tlds, err = promptForMultipleTLDs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	for _, tld := range tlds {
		if err := certs.GenerateAndPublishCertificate(tld, "."); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate for .%s: %v\n", tld, err)
			continue
		}
	}

	fmt.Printf("Generated certificates for %d TLD(s)\n", len(tlds))
}

func promptForTLD() (string, error) {
	prompt := promptui.Select{
		Label: "Select TLD",
		Items: []string{"nostr", "net", "com", "org", "other"},
	}

	index, result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	if index == 4 { // "other"
		customPrompt := promptui.Prompt{
			Label: "Enter custom TLD (without dot)",
		}
		return customPrompt.Run()
	}

	return result, nil
}

func promptForMultipleTLDs() ([]string, error) {
	var tlds []string

	commonTLDs := []string{"nostr", "net", "com", "org", "io", "dev"}

	for {
		// Create items with current selections marked
		items := make([]string, len(commonTLDs)+2)
		for i, tld := range commonTLDs {
			if contains(tlds, tld) {
				items[i] = fmt.Sprintf("✓ %s", tld)
			} else {
				items[i] = fmt.Sprintf("  %s", tld)
			}
		}
		items[len(commonTLDs)] = "Add custom TLD"
		items[len(commonTLDs)+1] = "Done"

		prompt := promptui.Select{
			Label: fmt.Sprintf("Select TLDs (currently selected: %s)", strings.Join(tlds, ", ")),
			Items: items,
		}

		index, _, err := prompt.Run()
		if err != nil {
			return nil, err
		}

		if index == len(commonTLDs)+1 { // "Done"
			break
		} else if index == len(commonTLDs) { // "Add custom TLD"
			customPrompt := promptui.Prompt{
				Label: "Enter custom TLD (without dot)",
			}
			customTLD, err := customPrompt.Run()
			if err != nil {
				return nil, err
			}
			if !contains(tlds, customTLD) {
				tlds = append(tlds, customTLD)
			}
		} else {
			// Toggle TLD selection
			tld := commonTLDs[index]
			if contains(tlds, tld) {
				tlds = remove(tlds, tld)
			} else {
				tlds = append(tlds, tld)
			}
		}
	}

	if len(tlds) == 0 {
		return nil, fmt.Errorf("no TLDs selected")
	}

	return tlds, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func remove(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

func promptForOutputDirectory() (string, error) {
	prompt := promptui.Prompt{
		Label:   "Output directory (press Enter for current directory)",
		Default: ".",
	}

	result, err := prompt.Run()
	if err != nil {
		return "", err
	}

	if result == "" {
		return ".", nil
	}

	return result, nil
}

func init() {
	rootCmd.AddCommand(certsCmd)
	certsCmd.AddCommand(listCertsCmd)
	certsCmd.AddCommand(addCertCmd)
	certsCmd.AddCommand(generateCertCmd)
	certsCmd.AddCommand(removeCertCmd)
	certsCmd.AddCommand(publishCertsCmd)
	certsCmd.AddCommand(showCertCmd)

	// Add flags for non-interactive use
	generateCertCmd.Flags().StringP("output", "o", ".", "Output directory for certificate files")
}
