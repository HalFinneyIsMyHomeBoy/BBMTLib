package cmd

import (
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/nostr-dns/nodns-cli/internal/auth"
	"github.com/nostr-dns/nodns-cli/internal/records"
	"github.com/spf13/cobra"
)

// recordsCmd represents the records command
var recordsCmd = &cobra.Command{
	Use:   "records",
	Short: "Manage DNS records",
	Long:  `Manage your DNS records published to Nostr`,
	Run: func(cmd *cobra.Command, args []string) {
		showRecordsMenu()
	},
}

var listRecordsCmd = &cobra.Command{
	Use:   "list",
	Short: "List current DNS records",
	Long:  `Display all DNS records for your domain`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		if err := records.ListCurrentRecords(); err != nil {
			fmt.Fprintf(os.Stderr, "Error listing records: %v\n", err)
			os.Exit(1)
		}
	},
}

var addRecordCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a DNS record",
	Long:  `Add a new DNS record (A, AAAA, CNAME, TXT, MX, SRV, etc.)`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		showAddRecordMenu()
	},
}

var removeRecordCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a DNS record",
	Long:  `Remove an existing DNS record`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		if err := records.InteractiveRemoveRecord(); err != nil {
			fmt.Fprintf(os.Stderr, "Error removing record: %v\n", err)
			os.Exit(1)
		}
	},
}

var publishRecordsCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current records from Nostr",
	Long:  `Display current DNS records published on Nostr relays`,
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		if err := records.ListCurrentRecords(); err != nil {
			fmt.Fprintf(os.Stderr, "Error listing records: %v\n", err)
			os.Exit(1)
		}
	},
}

// Helper commands for common record types
var addACmd = &cobra.Command{
	Use:   "a [name] [ip]",
	Short: "Add an A record",
	Long:  `Add an IPv4 A record`,
	Args:  cobra.RangeArgs(0, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var name, ip string
		var err error

		if len(args) >= 1 {
			name = args[0]
		} else {
			name, err = records.PromptForInput("Record name (e.g., '@' for root, 'www' for subdomain)")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		if len(args) >= 2 {
			ip = args[1]
		} else {
			ip, err = records.PromptForInput("IPv4 address")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Get TTL from flag or use default
		var ttl int
		if cmd != nil && cmd.Flags() != nil {
			ttl, _ = cmd.Flags().GetInt("ttl")
		}
		if ttl <= 0 {
			ttl = 3600 // Default TTL
		}

		if err := records.AddARecord(name, ip, ttl); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding A record: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added A record: %s -> %s (TTL: %d)\n", name, ip, ttl)
	},
}

var addCNAMECmd = &cobra.Command{
	Use:   "cname [name] [target]",
	Short: "Add a CNAME record",
	Long:  `Add a CNAME record`,
	Args:  cobra.RangeArgs(0, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var name, target string
		var err error

		if len(args) >= 1 {
			name = args[0]
		} else {
			name, err = records.PromptForInput("Record name (e.g., 'www', 'blog')")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		if len(args) >= 2 {
			target = args[1]
		} else {
			target, err = records.PromptForInput("Target domain")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Get TTL from flag or use default
		var ttl int
		if cmd != nil && cmd.Flags() != nil {
			ttl, _ = cmd.Flags().GetInt("ttl")
		}
		if ttl <= 0 {
			ttl = 3600 // Default TTL
		}

		if err := records.AddCNAMERecord(name, target, ttl); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding CNAME record: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added CNAME record: %s -> %s (TTL: %d)\n", name, target, ttl)
	},
}

var addTXTCmd = &cobra.Command{
	Use:   "txt [name] [value]",
	Short: "Add a TXT record",
	Long:  `Add a TXT record`,
	Args:  cobra.RangeArgs(0, 2),
	Run: func(cmd *cobra.Command, args []string) {
		if !auth.IsLoggedIn() {
			fmt.Println("Please login first using: nodns-cli login")
			os.Exit(1)
		}

		var name, value string
		var err error

		if len(args) >= 1 {
			name = args[0]
		} else {
			name, err = records.PromptForInput("Record name (e.g., '@' for root, '_dmarc' for DMARC)")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		if len(args) >= 2 {
			value = args[1]
		} else {
			value, err = records.PromptForInput("TXT value")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

		// Get TTL from flag or use default
		var ttl int
		if cmd != nil && cmd.Flags() != nil {
			ttl, _ = cmd.Flags().GetInt("ttl")
		}
		if ttl <= 0 {
			ttl = 3600 // Default TTL
		}

		if err := records.AddTXTRecord(name, value, ttl); err != nil {
			fmt.Fprintf(os.Stderr, "Error adding TXT record: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added TXT record: %s -> %s (TTL: %d)\n", name, value, ttl)
	},
}

func showRecordsMenu() {
	// Define menu items with their handlers
	type MenuItem struct {
		Label   string
		Handler func()
	}

	menuItems := []MenuItem{
		{
			Label: "List current records",
			Handler: func() {
				if err := records.ListCurrentRecordsWithActions(); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				}
			},
		},
		{
			Label: "Add A record (IPv4)",
			Handler: func() {
				addACmd.Run(nil, nil)
			},
		},
		{
			Label: "Add CNAME record",
			Handler: func() {
				addCNAMECmd.Run(nil, nil)
			},
		},
		{
			Label: "Add TXT record",
			Handler: func() {
				addTXTCmd.Run(nil, nil)
			},
		},
		{
			Label: "Add other record type",
			Handler: func() {
				showAddRecordMenu()
			},
		},
		{
			Label: "Remove record",
			Handler: func() {
				removeRecordCmd.Run(nil, nil)
			},
		},
		{
			Label: "Back to main menu",
			Handler: func() {
				return
			},
		},
	}

	// Extract labels for the promptui
	labels := make([]string, len(menuItems))
	for i, item := range menuItems {
		labels[i] = item.Label
	}

	prompt := promptui.Select{
		Label: "DNS Records Management",
		Items: labels,
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Execute the selected handler
	if index >= 0 && index < len(menuItems) {
		if menuItems[index].Label == "Back to main menu" {
			return
		}
		menuItems[index].Handler()
	} else {
		fmt.Fprintf(os.Stderr, "Invalid selection\n")
		os.Exit(1)
	}
}

func showAddRecordMenu() {
	// Define menu items with their handlers
	type MenuItem struct {
		Label   string
		Handler func()
	}

	menuItems := []MenuItem{
		{
			Label: "A (IPv4 address)",
			Handler: func() {
				addACmd.Run(nil, nil)
			},
		},
		{
			Label: "AAAA (IPv6 address)",
			Handler: func() {
				if err := records.AddAAAARecord(); err != nil {
					fmt.Fprintf(os.Stderr, "Error adding AAAA record: %v\n", err)
				}
			},
		},
		{
			Label: "CNAME (canonical name)",
			Handler: func() {
				addCNAMECmd.Run(nil, nil)
			},
		},
		{
			Label: "TXT (text record)",
			Handler: func() {
				addTXTCmd.Run(nil, nil)
			},
		},
		{
			Label: "MX (mail exchange)",
			Handler: func() {
				if err := records.AddMXRecord(); err != nil {
					fmt.Fprintf(os.Stderr, "Error adding MX record: %v\n", err)
				}
			},
		},
		{
			Label: "SRV (service record)",
			Handler: func() {
				if err := records.AddSRVRecord(); err != nil {
					fmt.Fprintf(os.Stderr, "Error adding SRV record: %v\n", err)
				}
			},
		},
		{
			Label: "NS (name server) - Not implemented",
			Handler: func() {
				fmt.Printf("NS records not yet implemented\n")
			},
		},
		{
			Label: "PTR (pointer record) - Not implemented",
			Handler: func() {
				fmt.Printf("PTR records not yet implemented\n")
			},
		},
		{
			Label: "Custom record type - Not implemented",
			Handler: func() {
				fmt.Printf("Custom record types not yet implemented\n")
			},
		},
	}

	// Extract labels for the promptui
	labels := make([]string, len(menuItems))
	for i, item := range menuItems {
		labels[i] = item.Label
	}

	prompt := promptui.Select{
		Label: "Select record type to add",
		Items: labels,
	}

	index, _, err := prompt.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Execute the selected handler
	if index >= 0 && index < len(menuItems) {
		menuItems[index].Handler()
	} else {
		fmt.Fprintf(os.Stderr, "Invalid selection\n")
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(recordsCmd)
	recordsCmd.AddCommand(listRecordsCmd)
	recordsCmd.AddCommand(addRecordCmd)
	recordsCmd.AddCommand(removeRecordCmd)
	recordsCmd.AddCommand(publishRecordsCmd)

	// Helper commands
	addRecordCmd.AddCommand(addACmd)
	addRecordCmd.AddCommand(addCNAMECmd)
	addRecordCmd.AddCommand(addTXTCmd)

	// Add TTL flags to record commands for non-interactive use
	addACmd.Flags().Int("ttl", 3600, "TTL value in seconds")
	addCNAMECmd.Flags().Int("ttl", 3600, "TTL value in seconds")
	addTXTCmd.Flags().Int("ttl", 3600, "TTL value in seconds")
}
