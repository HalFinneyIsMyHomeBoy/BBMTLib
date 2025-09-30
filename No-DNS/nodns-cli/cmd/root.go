package cmd

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/nostr-dns/nodns-cli/internal/auth"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nodns",
	Short: "Manage Nostr DNS records and certificates",
	Long: `A command-line tool for managing decentralized DNS records and SSL certificates
using the Nostr protocol. Features include:

- Authentication with various methods (nsec, Amber, Bunker)
- DNS record management (A, AAAA, CNAME, TXT, MX, SRV, etc.)
- SSL certificate management with automatic generation
- Multi-platform support

Run without arguments for interactive menu, or use specific commands for non-interactive mode.`,
	Run: func(cmd *cobra.Command, args []string) {
		showMainMenu()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.nodns-cli.yaml)")
	rootCmd.PersistentFlags().String("relays", "", "comma-separated list of Nostr relays")

	// Bind flags to viper
	viper.BindPFlag("relays", rootCmd.PersistentFlags().Lookup("relays"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".nodns-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".nodns-cli")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// Set default values
	viper.SetDefault("relays", "wss://relay.damus.io,wss://nos.lol,wss://relay.snort.social")

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func showMainMenu() {
	for {
		// Check login status
		isLoggedIn := auth.IsLoggedIn()
		var statusText string
		if isLoggedIn {
			user, err := auth.GetCurrentUser()
			if err != nil {
				statusText = "❌ Authentication Error"
			} else {
				statusText = fmt.Sprintf("✅ Logged in as %s", user.NPub)
			}
		} else {
			statusText = "❌ Not logged in"
		}

		fmt.Println("\n" + statusText)
		fmt.Println("=====================================")

		// Define menu items with their handlers
		type MenuItem struct {
			Label   string
			Handler func()
		}

		menuItems := []MenuItem{
			{
				Label: "🔐 Login / Authentication",
				Handler: func() {
					loginCmd.Run(nil, nil)
				},
			},
			{
				Label: "📡 DNS Records Management",
				Handler: func() {
					if !auth.IsLoggedIn() {
						fmt.Println("Please login first")
						return
					}
					showRecordsMenu()
				},
			},
			{
				Label: "🔒 Certificate Management",
				Handler: func() {
					if !auth.IsLoggedIn() {
						fmt.Println("Please login first")
						return
					}
					showCertsMenu()
				},
			},
			{
				Label: "ℹ️  Show Current Status",
				Handler: func() {
					showStatusInfo()
				},
			},
			{
				Label: "❌ Exit",
				Handler: func() {
					fmt.Println("Goodbye!")
					os.Exit(0)
				},
			},
		}

		// Extract labels for the promptui
		labels := make([]string, len(menuItems))
		for i, item := range menuItems {
			labels[i] = item.Label
		}

		prompt := promptui.Select{
			Label: "Nostr DNS - Main Menu",
			Items: labels,
		}

		index, _, err := prompt.Run()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		// Execute the selected handler
		if index >= 0 && index < len(menuItems) {
			menuItems[index].Handler()
		}
	}
}

func showStatusInfo() {
	isLoggedIn := auth.IsLoggedIn()

	fmt.Println("\n🔍 System Status")
	fmt.Println("================")

	if isLoggedIn {
		user, err := auth.GetCurrentUser()
		if err != nil {
			fmt.Printf("❌ Authentication Error: %v\n", err)
		} else {
			fmt.Printf("✅ Logged in as: %s\n", user.NPub)
			fmt.Printf("🌐 Domain: %s.nostr\n", user.NPub)
		}
	} else {
		fmt.Println("❌ Not logged in")
		fmt.Println("💡 Use 'Login / Authentication' to get started")
	}

	// Show relay configuration
	relays := viper.GetString("relays")
	if relays != "" {
		fmt.Printf("📡 Configured relays: %s\n", relays)
	} else {
		fmt.Println("📡 Using default relays")
	}

	fmt.Println("\n💡 Available Commands:")
	fmt.Println("   Interactive: nodns (this menu)")
	fmt.Println("   Records: nodns records [list|add|remove]")
	fmt.Println("   Certificates: nodns certs [list|generate|add|remove]")
	fmt.Println("   Login: nodns login [nsec|amber|bunker]")

	fmt.Println("\nPress Enter to continue...")
	fmt.Scanln()
}
