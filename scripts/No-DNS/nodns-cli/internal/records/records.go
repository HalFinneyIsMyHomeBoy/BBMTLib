package records

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/manifoldco/promptui"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nostr-dns/nodns-cli/internal/auth"
	"github.com/spf13/viper"
)

// NostrRecord represents a DNS record as stored in Nostr events
type NostrRecord struct {
	Type string
	Name string
	Pos1 string
	Pos2 string
	Pos3 string
	Pos4 string
	Pos5 string
	Pos6 string
	Pos7 string
	TTL  string
}

// FetchCurrentRecords retrieves the current DNS records for the logged-in user from Nostr
func FetchCurrentRecords() ([]NostrRecord, error) {
	user, err := auth.GetCurrentUser()
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}

	// Get relays from config
	relayURLs := strings.Split(viper.GetString("relays"), ",")
	if len(relayURLs) == 0 {
		return nil, fmt.Errorf("no relays configured")
	}

	ctx := context.Background()

	// Query for the most recent DNS record event
	filter := nostr.Filter{
		Kinds:   []int{11111}, // DNS record events
		Authors: []string{user.PublicKey},
		Limit:   1, // Get most recent event only
	}

	for _, relayURL := range relayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			fmt.Printf("Failed to connect to relay %s: %v\n", relayURL, err)
			continue
		}

		// Subscribe to events
		sub, err := relay.Subscribe(ctx, []nostr.Filter{filter})
		if err != nil {
			fmt.Printf("Failed to subscribe to relay %s: %v\n", relayURL, err)
			relay.Close()
			continue
		}

		// Wait for events with timeout
		timeout := time.After(5 * time.Second)
		var latestEvent *nostr.Event

	eventLoop:
		for {
			select {
			case event := <-sub.Events:
				if latestEvent == nil || event.CreatedAt > latestEvent.CreatedAt {
					latestEvent = event
				}
			case <-sub.EndOfStoredEvents:
				break eventLoop
			case <-timeout:
				break eventLoop
			}
		}

		sub.Unsub()
		relay.Close()

		if latestEvent != nil {
			// Parse records from event and return
			return parseRecordsFromEvent(latestEvent), nil
		}
	}

	// No records found
	return []NostrRecord{}, nil
}

// PublishRecords publishes DNS records to Nostr (replaces any existing records)
func PublishRecords(records []NostrRecord) error {
	user, err := auth.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Create new DNS record event
	event := &nostr.Event{
		Kind:      11111,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Content:   "", // MUST be empty per spec
		Tags:      []nostr.Tag{},
	}

	// Convert records to Nostr tags with exact 11-element format
	for _, record := range records {
		tag := nostr.Tag{
			"record",
			record.Type,
			record.Name,
			record.Pos1,
			record.Pos2,
			record.Pos3,
			record.Pos4,
			record.Pos5,
			record.Pos6,
			record.Pos7,
			record.TTL,
		}
		event.Tags = append(event.Tags, tag)
	}

	// Sign the event
	if err := event.Sign(user.PrivateKey); err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	// Get relays from config
	relayURLs := strings.Split(viper.GetString("relays"), ",")
	if len(relayURLs) == 0 {
		return fmt.Errorf("no relays configured")
	}

	// Publish to relays
	ctx := context.Background()
	published := 0

	for _, relayURL := range relayURLs {
		relayURL = strings.TrimSpace(relayURL)
		if relayURL == "" {
			continue
		}

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			fmt.Printf("Failed to connect to relay %s: %v\n", relayURL, err)
			continue
		}

		if err := relay.Publish(ctx, *event); err != nil {
			fmt.Printf("Failed to publish to relay %s: %v\n", relayURL, err)
		} else {
			fmt.Printf("Published to relay: %s\n", relayURL)
			published++
		}

		relay.Close()
	}

	if published == 0 {
		return fmt.Errorf("failed to publish to any relay")
	}

	fmt.Printf("Successfully published %d records to %d relays\n", len(records), published)
	return nil
}

// AddRecord adds a DNS record and immediately publishes to Nostr
func AddRecord(newRecord NostrRecord) error {
	// Fetch current records
	currentRecords, err := FetchCurrentRecords()
	if err != nil {
		return fmt.Errorf("failed to fetch current records: %w", err)
	}

	// Check for existing record and replace it
	recordKey := fmt.Sprintf("%s:%s", newRecord.Type, newRecord.Name)
	found := false
	for i, existing := range currentRecords {
		existingKey := fmt.Sprintf("%s:%s", existing.Type, existing.Name)
		if existingKey == recordKey {
			currentRecords[i] = newRecord
			found = true
			fmt.Printf("Replaced existing %s record for %s\n", newRecord.Type, newRecord.Name)
			break
		}
	}

	if !found {
		currentRecords = append(currentRecords, newRecord)
		fmt.Printf("Added new %s record for %s\n", newRecord.Type, newRecord.Name)
	}

	// Immediately publish the updated records
	return PublishRecords(currentRecords)
}

// RemoveRecord removes a DNS record and immediately publishes to Nostr
func RemoveRecord(recordType, recordName string) error {
	// Fetch current records
	currentRecords, err := FetchCurrentRecords()
	if err != nil {
		return fmt.Errorf("failed to fetch current records: %w", err)
	}

	// Find and remove the record
	recordKey := fmt.Sprintf("%s:%s", recordType, recordName)
	found := false
	var updatedRecords []NostrRecord

	for _, record := range currentRecords {
		existingKey := fmt.Sprintf("%s:%s", record.Type, record.Name)
		if existingKey != recordKey {
			updatedRecords = append(updatedRecords, record)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("record not found: %s %s", recordType, recordName)
	}

	fmt.Printf("Removed %s record for %s\n", recordType, recordName)

	// Immediately publish the updated records
	return PublishRecords(updatedRecords)
}

// ListCurrentRecords shows all current DNS records from Nostr
func ListCurrentRecords() error {
	user, err := auth.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	fmt.Printf("Fetching DNS records for %s from Nostr...\n", user.NPub)

	records, err := FetchCurrentRecords()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Printf("No DNS records found on Nostr for %s.nostr\n", user.NPub)
		fmt.Println("Use 'nodns records add' to create your first record.")
		return nil
	}

	fmt.Printf("\nDNS Records for %s.nostr:\n", user.NPub)
	fmt.Println("========================================")

	for i, record := range records {
		fmt.Printf("%d. %s\t%s\t-> %s", i+1, record.Type, record.Name, record.Pos1)
		if record.Pos2 != "" {
			fmt.Printf(" %s", record.Pos2)
		}
		if record.Pos3 != "" {
			fmt.Printf(" %s", record.Pos3)
		}
		if record.Pos4 != "" {
			fmt.Printf(" %s", record.Pos4)
		}
		if record.TTL != "" && record.TTL != "3600" {
			fmt.Printf(" (TTL: %s)", record.TTL)
		}
		fmt.Println()
	}

	fmt.Printf("\nTotal: %d records\n", len(records))
	return nil
}

// ListCurrentRecordsWithActions shows records and offers delete/edit options
func ListCurrentRecordsWithActions() error {
	user, err := auth.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	fmt.Printf("Fetching DNS records for %s from Nostr...\n", user.NPub)

	records, err := FetchCurrentRecords()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Printf("No DNS records found on Nostr for %s.nostr\n", user.NPub)
		fmt.Println("Use 'nodns records add' to create your first record.")
		return nil
	}

	fmt.Printf("\nDNS Records for %s.nostr:\n", user.NPub)
	fmt.Println("========================================")

	for i, record := range records {
		fmt.Printf("%d. %s\t%s\t-> %s", i+1, record.Type, record.Name, record.Pos1)
		if record.Pos2 != "" {
			fmt.Printf(" %s", record.Pos2)
		}
		if record.Pos3 != "" {
			fmt.Printf(" %s", record.Pos3)
		}
		if record.Pos4 != "" {
			fmt.Printf(" %s", record.Pos4)
		}
		if record.TTL != "" && record.TTL != "3600" {
			fmt.Printf(" (TTL: %s)", record.TTL)
		}
		fmt.Println()
	}

	fmt.Printf("\nTotal: %d records\n", len(records))

	// Offer action options
	type ActionItem struct {
		Label   string
		Handler func() error
	}

	actionItems := []ActionItem{
		{
			Label: "Delete a record",
			Handler: func() error {
				return InteractiveRemoveRecord()
			},
		},
		{
			Label: "Add new record",
			Handler: func() error {
				// This would trigger the add menu - for now just return
				fmt.Println("Use 'nodns records add' to add a new record")
				return nil
			},
		},
		{
			Label: "Done",
			Handler: func() error {
				return nil
			},
		},
	}

	// Extract labels for the promptui
	labels := make([]string, len(actionItems))
	for i, item := range actionItems {
		labels[i] = item.Label
	}

	prompt := promptui.Select{
		Label: "What would you like to do?",
		Items: labels,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return err
	}

	// Execute the selected action
	if index >= 0 && index < len(actionItems) {
		return actionItems[index].Handler()
	}

	return nil
}

// Interactive record removal with selection
func InteractiveRemoveRecord() error {
	// Fetch current records
	records, err := FetchCurrentRecords()
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Println("No records to remove.")
		return nil
	}

	// Create display items
	items := make([]string, len(records))
	for i, record := range records {
		items[i] = fmt.Sprintf("%s %s -> %s", record.Type, record.Name, record.Pos1)
	}

	prompt := promptui.Select{
		Label: "Select record to remove",
		Items: items,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return err
	}

	selectedRecord := records[index]
	return RemoveRecord(selectedRecord.Type, selectedRecord.Name)
}

// Helper functions for adding specific record types
func AddARecord(name, ip string, ttl int) error {
	if err := validateIPv4(ip); err != nil {
		return fmt.Errorf("invalid IPv4 address: %w", err)
	}

	record := NostrRecord{
		Type: "A",
		Name: name,
		Pos1: ip,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

func AddAAAARecord() error {
	name, err := PromptForInput("Record name")
	if err != nil {
		return err
	}

	ipv6, err := PromptForInput("IPv6 address")
	if err != nil {
		return err
	}

	if err := validateIPv6(ipv6); err != nil {
		return fmt.Errorf("invalid IPv6 address: %w", err)
	}

	ttl, err := PromptForTTL()
	if err != nil {
		return err
	}

	record := NostrRecord{
		Type: "AAAA",
		Name: name,
		Pos1: ipv6,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

func AddCNAMERecord(name, target string, ttl int) error {
	record := NostrRecord{
		Type: "CNAME",
		Name: name,
		Pos1: target,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

func AddTXTRecord(name, value string, ttl int) error {
	record := NostrRecord{
		Type: "TXT",
		Name: name,
		Pos1: value,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

func AddMXRecord() error {
	name, err := PromptForInput("Record name (usually '@' for root)")
	if err != nil {
		return err
	}

	priority, err := PromptForInput("Priority (e.g., 10)")
	if err != nil {
		return err
	}

	mailserver, err := PromptForInput("Mail server (e.g., mail.example.com)")
	if err != nil {
		return err
	}

	ttl, err := PromptForTTL()
	if err != nil {
		return err
	}

	record := NostrRecord{
		Type: "MX",
		Name: name,
		Pos1: priority,
		Pos2: mailserver,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

func AddSRVRecord() error {
	name, err := PromptForInput("Service name (e.g., _sip._tcp)")
	if err != nil {
		return err
	}

	priority, err := PromptForInput("Priority (e.g., 10)")
	if err != nil {
		return err
	}

	weight, err := PromptForInput("Weight (e.g., 5)")
	if err != nil {
		return err
	}

	port, err := PromptForInput("Port (e.g., 5060)")
	if err != nil {
		return err
	}

	target, err := PromptForInput("Target server")
	if err != nil {
		return err
	}

	ttl, err := PromptForTTL()
	if err != nil {
		return err
	}

	record := NostrRecord{
		Type: "SRV",
		Name: name,
		Pos1: priority,
		Pos2: weight,
		Pos3: port,
		Pos4: target,
		TTL:  strconv.Itoa(ttl),
	}

	return AddRecord(record)
}

// parseRecordsFromEvent extracts DNS records from a Nostr event
func parseRecordsFromEvent(event *nostr.Event) []NostrRecord {
	var records []NostrRecord

	for _, tag := range event.Tags {
		if len(tag) >= 11 && tag[0] == "record" {
			record := NostrRecord{
				Type: tag[1],
				Name: tag[2],
				Pos1: tag[3],
				Pos2: tag[4],
				Pos3: tag[5],
				Pos4: tag[6],
				Pos5: tag[7],
				Pos6: tag[8],
				Pos7: tag[9],
				TTL:  tag[10],
			}
			records = append(records, record)
		}
	}

	return records
}

// Validation helpers
func validateIPv4(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("invalid IPv4 address")
	}
	return nil
}

func validateIPv6(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return fmt.Errorf("invalid IPv6 address")
	}
	return nil
}

func PromptForInput(label string) (string, error) {
	prompt := promptui.Prompt{
		Label: label,
	}
	return prompt.Run()
}

func PromptForTTL() (int, error) {
	prompt := promptui.Prompt{
		Label:   "TTL (seconds, press Enter for default 3600)",
		Default: "3600",
		Validate: func(input string) error {
			if input == "" {
				return nil
			}
			_, err := strconv.Atoi(input)
			return err
		},
	}

	result, err := prompt.Run()
	if err != nil {
		return 0, err
	}

	if result == "" {
		return 3600, nil
	}

	return strconv.Atoi(result)
}
