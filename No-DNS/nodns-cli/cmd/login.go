package cmd

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/nostr-dns/nodns-cli/internal/auth"
	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to manage your Nostr DNS records",
	Long: `Login using various methods to authenticate and manage your Nostr DNS records:

- Generate a new key pair
- Import from nsec (hex or bech32)
- Login via Amber (QR code)
- Login via Bunker URL`,
	Run: func(cmd *cobra.Command, args []string) {
		showLoginMenu()
	},
}

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new Nostr key pair",
	Long:  `Generate a new Nostr key pair and save it for managing DNS records`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := auth.GenerateNewKey(); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
	},
}

var nsecCmd = &cobra.Command{
	Use:   "nsec [nsec_key]",
	Short: "Login with nsec private key",
	Long:  `Login using your nsec private key (hex or bech32 format)`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var nsecKey string
		var err error

		if len(args) == 0 {
			// Prompt for nsec key securely
			prompt := promptui.Prompt{
				Label: "Enter your nsec key",
				Mask:  '*',
				Validate: func(input string) error {
					return auth.ValidateNsecKey(input)
				},
			}
			nsecKey, err = prompt.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading nsec: %v\n", err)
				os.Exit(1)
			}
		} else {
			nsecKey = args[0]
		}

		if err := auth.LoginWithNsec(nsecKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error logging in with nsec: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully logged in with nsec!")
	},
}

var amberCmd = &cobra.Command{
	Use:   "amber",
	Short: "Login with Amber (QR code)",
	Long:  `Login using Amber mobile app via QR code scanning`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := auth.LoginWithAmber(); err != nil {
			fmt.Fprintf(os.Stderr, "Error logging in with Amber: %v\n", err)
			os.Exit(1)
		}
	},
}

var bunkerCmd = &cobra.Command{
	Use:   "bunker [bunker_url]",
	Short: "Login with Bunker URL",
	Long:  `Login using a Nostr Connect (NIP-46) Bunker URL`,
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var bunkerURL string
		var err error

		if len(args) == 0 {
			// Prompt for bunker URL
			prompt := promptui.Prompt{
				Label: "Enter Bunker URL",
				Validate: func(input string) error {
					return auth.ValidateBunkerURL(input)
				},
			}
			bunkerURL, err = prompt.Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading bunker URL: %v\n", err)
				os.Exit(1)
			}
		} else {
			bunkerURL = args[0]
		}

		if err := auth.LoginWithBunker(bunkerURL); err != nil {
			fmt.Fprintf(os.Stderr, "Error logging in with bunker: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully logged in with bunker!")
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current login status",
	Long:  `Display information about the currently logged in account`,
	Run: func(cmd *cobra.Command, args []string) {
		status, err := auth.GetLoginStatus()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting login status: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(status)
	},
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout and clear stored credentials",
	Long:  `Remove stored authentication credentials`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := auth.Logout(); err != nil {
			fmt.Fprintf(os.Stderr, "Error logging out: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully logged out!")
	},
}

func showLoginMenu() {
	prompt := promptui.Select{
		Label: "Select login method",
		Items: []string{
			"Generate new key",
			"Login with nsec",
			"Login with Amber (QR)",
			"Login with Bunker URL",
			"Show status",
			"Logout",
		},
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	switch index {
	case 0:
		generateCmd.Run(nil, nil)
	case 1:
		nsecCmd.Run(nil, nil)
	case 2:
		amberCmd.Run(nil, nil)
	case 3:
		bunkerCmd.Run(nil, nil)
	case 4:
		statusCmd.Run(nil, nil)
	case 5:
		logoutCmd.Run(nil, nil)
	}
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.AddCommand(generateCmd)
	loginCmd.AddCommand(nsecCmd)
	loginCmd.AddCommand(amberCmd)
	loginCmd.AddCommand(bunkerCmd)
	loginCmd.AddCommand(statusCmd)
	loginCmd.AddCommand(logoutCmd)
}
