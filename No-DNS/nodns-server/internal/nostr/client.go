package nostr

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/sirupsen/logrus"
)

// Client handles Nostr relay connections and event fetching
type Client struct {
	relays  []string
	timeout time.Duration
}

// EventBundle contains both DNS records and certificates for a pubkey
type EventBundle struct {
	DNSRecords   *nostr.Event            // kind 11111 event
	Certificates map[string]*nostr.Event // TLD -> kind 30003 event
}

// DNSRecord represents a parsed DNS record from Nostr tags
type DNSRecord struct {
	Type string   // A, AAAA, CNAME, TXT, MX, SRV, etc.
	Name string   // "@" for root, subdomain name, or FQDN
	Data []string // pos1-pos7 data fields
	TTL  uint32   // TTL in seconds (default 3600)
}

// Certificate represents a parsed certificate from Nostr events
type Certificate struct {
	TLD         string
	PEM         string
	Expiry      time.Time
	EventID     string
	Fingerprint string
}

// NewClient creates a new Nostr client
func NewClient(relays []string) *Client {
	return &Client{
		relays:  relays,
		timeout: 10 * time.Second,
	}
}

// Close closes all relay connections
func (c *Client) Close() {
	// Connection cleanup is handled by go-nostr automatically
	logrus.Debug("Nostr client closed")
}

// FetchEventsForPubkey fetches both DNS records and certificates for a pubkey
func (c *Client) FetchEventsForPubkey(pubkey string) (*EventBundle, error) {
	logrus.Debugf("Fetching events for pubkey: %s", pubkey)

	filter := nostr.Filter{
		Kinds:   []int{11111, 30003}, // DNS records and certificates
		Authors: []string{pubkey},
		Limit:   50, // Allow multiple certificates
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	bundle := &EventBundle{
		Certificates: make(map[string]*nostr.Event),
	}

	// Try each relay until we get results
	for _, relayURL := range c.relays {
		logrus.Debugf("Connecting to relay: %s", relayURL)

		relay, err := nostr.RelayConnect(ctx, relayURL)
		if err != nil {
			logrus.Warnf("Failed to connect to relay %s: %v", relayURL, err)
			continue
		}

		sub, err := relay.Subscribe(ctx, []nostr.Filter{filter})
		if err != nil {
			logrus.Warnf("Failed to subscribe to relay %s: %v", relayURL, err)
			relay.Close()
			continue
		}

		// Collect events with timeout
		eventTimeout := time.After(5 * time.Second)
		eventCount := 0

	eventLoop:
		for {
			select {
			case event := <-sub.Events:
				eventCount++
				logrus.Debugf("Received event kind %d from %s", event.Kind, relayURL)

				switch event.Kind {
				case 11111:
					// Keep latest DNS record event
					if bundle.DNSRecords == nil || event.CreatedAt > bundle.DNSRecords.CreatedAt {
						bundle.DNSRecords = event
						logrus.Debugf("Updated DNS records event (created_at: %d)", event.CreatedAt)
					}
				case 30003:
					// Extract TLD from 'd' tag
					tld := extractTLDFromEvent(event)
					if tld != "" {
						// Keep latest certificate per TLD
						if existing, exists := bundle.Certificates[tld]; !exists || event.CreatedAt > existing.CreatedAt {
							bundle.Certificates[tld] = event
							logrus.Debugf("Updated certificate for TLD %s (created_at: %d)", tld, event.CreatedAt)
						}
					}
				}

			case <-sub.EndOfStoredEvents:
				logrus.Debugf("End of stored events from %s", relayURL)
				break eventLoop
			case <-eventTimeout:
				logrus.Debugf("Event timeout from %s", relayURL)
				break eventLoop
			case <-ctx.Done():
				logrus.Debugf("Context cancelled for %s", relayURL)
				break eventLoop
			}
		}

		sub.Unsub()
		relay.Close()

		logrus.Debugf("Collected %d events from %s", eventCount, relayURL)

		// Stop if we have DNS records (certificates are optional)
		if bundle.DNSRecords != nil {
			logrus.Debugf("Found DNS records, stopping relay iteration")
			break
		}
	}

	if bundle.DNSRecords == nil {
		return nil, fmt.Errorf("no DNS record events found for pubkey %s", pubkey)
	}

	logrus.Infof("Successfully fetched events for pubkey %s: DNS records + %d certificates",
		pubkey, len(bundle.Certificates))
	return bundle, nil
}

// ParseDNSRecords parses DNS records from a kind 11111 event
func (c *Client) ParseDNSRecords(event *nostr.Event) ([]*DNSRecord, error) {
	if event.Kind != 11111 {
		return nil, fmt.Errorf("invalid event kind %d, expected 11111", event.Kind)
	}

	// Content must be empty for DNS record events
	if event.Content != "" {
		return nil, errors.New("DNS record event content must be empty")
	}

	var records []*DNSRecord

	for _, tag := range event.Tags {
		if len(tag) == 11 && tag[0] == "record" {
			record, err := parseRecordTag(tag)
			if err != nil {
				logrus.Warnf("Invalid record tag: %v", err)
				continue
			}
			records = append(records, record)
		}
	}

	if len(records) == 0 {
		return nil, errors.New("no valid record tags found")
	}

	logrus.Debugf("Parsed %d DNS records from event", len(records))
	return records, nil
}

// ParseCertificates parses certificates from kind 30003 events
func (c *Client) ParseCertificates(events map[string]*nostr.Event) ([]*Certificate, error) {
	var certificates []*Certificate

	for tld, event := range events {
		if event.Kind != 30003 {
			logrus.Warnf("Invalid certificate event kind %d for TLD %s", event.Kind, tld)
			continue
		}

		// Skip deleted certificates (empty content)
		if event.Content == "" {
			logrus.Debugf("Skipping deleted certificate for TLD %s", tld)
			continue
		}

		// Validate and clean PEM data before creating certificate
		cleanPEM, err := validateAndCleanPEM(event.Content, tld)
		if err != nil {
			logrus.Warnf("CERT_VALIDATION: Skipping invalid certificate for TLD %s: %v", tld, err)
			continue
		}

		cert := &Certificate{
			TLD:         tld,
			PEM:         cleanPEM,
			EventID:     event.ID,
			Fingerprint: calculateEventFingerprint(event),
		}

		// Extract expiry from tags
		for _, tag := range event.Tags {
			if len(tag) >= 2 && tag[0] == "expiry" {
				if timestamp, err := strconv.ParseInt(tag[1], 10, 64); err == nil {
					cert.Expiry = time.Unix(timestamp, 0)
				}
			}
		}

		certificates = append(certificates, cert)
		logrus.Debugf("Parsed certificate for TLD %s (expires: %s)", tld, cert.Expiry.Format("2006-01-02"))
	}

	return certificates, nil
}

// extractTLDFromEvent extracts the TLD from a certificate event's 'd' tag
func extractTLDFromEvent(event *nostr.Event) string {
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "d" {
			return tag[1]
		}
	}
	return ""
}

// parseRecordTag parses a record tag into a DNSRecord
// Format: ["record", "TYPE", "name", "pos1", "pos2", "pos3", "pos4", "pos5", "pos6", "pos7", "ttl"]
func parseRecordTag(tag []string) (*DNSRecord, error) {
	if len(tag) != 11 {
		return nil, fmt.Errorf("record tag must have exactly 11 elements, got %d", len(tag))
	}

	if tag[0] != "record" {
		return nil, fmt.Errorf("first element must be 'record', got '%s'", tag[0])
	}

	recordType := strings.ToUpper(tag[1])
	if recordType == "" {
		return nil, errors.New("record type cannot be empty")
	}

	name := tag[2]
	if name == "" {
		return nil, errors.New("record name cannot be empty")
	}

	// Parse TTL
	ttl := uint32(3600) // default
	if tag[10] != "" {
		if parsed, err := strconv.ParseUint(tag[10], 10, 32); err == nil {
			ttl = uint32(parsed)
		} else {
			return nil, fmt.Errorf("invalid TTL value: %s", tag[10])
		}
	}

	// Extract data fields (pos1-pos7)
	data := make([]string, 7)
	copy(data, tag[3:10])

	record := &DNSRecord{
		Type: recordType,
		Name: name,
		Data: data,
		TTL:  ttl,
	}

	// Validate record based on type
	if err := validateDNSRecord(record); err != nil {
		return nil, fmt.Errorf("invalid %s record: %w", recordType, err)
	}

	return record, nil
}

// validateDNSRecord performs basic validation of DNS records
func validateDNSRecord(record *DNSRecord) error {
	switch record.Type {
	case "A":
		if record.Data[0] == "" {
			return errors.New("A record requires IPv4 address in pos1")
		}
		// Basic IPv4 validation
		parts := strings.Split(record.Data[0], ".")
		if len(parts) != 4 {
			return errors.New("invalid IPv4 address format")
		}

	case "AAAA":
		if record.Data[0] == "" {
			return errors.New("AAAA record requires IPv6 address in pos1")
		}
		// Basic IPv6 validation
		if !strings.Contains(record.Data[0], ":") {
			return errors.New("invalid IPv6 address format")
		}

	case "CNAME", "NS", "PTR":
		if record.Data[0] == "" {
			return fmt.Errorf("%s record requires target domain in pos1", record.Type)
		}

	case "TXT":
		if record.Data[0] == "" {
			return errors.New("TXT record requires text content in pos1")
		}

	case "MX":
		if record.Data[0] == "" || record.Data[1] == "" {
			return errors.New("MX record requires priority in pos1 and mail server in pos2")
		}

	case "SRV":
		if record.Data[0] == "" || record.Data[1] == "" || record.Data[2] == "" || record.Data[3] == "" {
			return errors.New("SRV record requires priority, weight, port, and target")
		}
	}

	return nil
}

// validateAndCleanPEM validates and cleans PEM certificate data from Nostr events
func validateAndCleanPEM(pemData, tld string) (string, error) {
	if pemData == "" {
		return "", fmt.Errorf("empty PEM data")
	}

	// Remove common issues
	// 1. Remove UTF-8 BOM if present
	pemData = strings.TrimPrefix(pemData, "\ufeff")

	// 2. Normalize line endings
	pemData = strings.ReplaceAll(pemData, "\r\n", "\n")
	pemData = strings.ReplaceAll(pemData, "\r", "\n")

	// 3. Trim excessive whitespace
	pemData = strings.TrimSpace(pemData)

	// 4. Validate basic PEM structure
	if !strings.Contains(pemData, "-----BEGIN") {
		return "", fmt.Errorf("missing PEM BEGIN header")
	}
	if !strings.Contains(pemData, "-----END") {
		return "", fmt.Errorf("missing PEM END header")
	}

	// 5. Check for valid certificate headers
	validHeaders := []string{
		"-----BEGIN CERTIFICATE-----",
		"-----BEGIN X509 CERTIFICATE-----",
		"-----BEGIN TRUSTED CERTIFICATE-----",
	}
	hasValidHeader := false
	for _, header := range validHeaders {
		if strings.Contains(pemData, header) {
			hasValidHeader = true
			break
		}
	}
	if !hasValidHeader {
		return "", fmt.Errorf("no valid certificate header found")
	}

	// 6. Check for binary data (should not contain null bytes)
	if strings.Contains(pemData, "\x00") {
		return "", fmt.Errorf("PEM data contains null bytes (likely binary data)")
	}

	// 7. Ensure proper line ending
	if !strings.HasSuffix(pemData, "\n") {
		pemData += "\n"
	}

	// 8. Validate that we can decode it as PEM
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("PEM decoding failed")
	}
	if block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}

	// 9. Validate that we can parse it as X.509 certificate
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("X.509 certificate parsing failed: %w", err)
	}

	logrus.Debugf("CERT_VALIDATION: Successfully validated PEM certificate for TLD %s (%d chars)", tld, len(pemData))
	return pemData, nil
}

// calculateEventFingerprint calculates a SHA-256 fingerprint of the event
func calculateEventFingerprint(event *nostr.Event) string {
	hash := sha256.Sum256([]byte(event.ID))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes for shorter fingerprint
}

// ConvertNpubToPubkey converts an npub to hex pubkey
func ConvertNpubToPubkey(npub string) (string, error) {
	prefix, data, err := nip19.Decode(npub)
	if err != nil {
		return "", fmt.Errorf("invalid npub format: %w", err)
	}
	if prefix != "npub" {
		return "", fmt.Errorf("not an npub key")
	}
	return data.(string), nil
}

// ExtractNpubFromDomain extracts npub from domain formats
func ExtractNpubFromDomain(domain string) (string, error) {
	// Remove TLD suffixes (.nostr, .net, etc.)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	// Take everything except the last part (TLD)
	domainPart := strings.Join(parts[:len(parts)-1], ".")

	// Check if it looks like an npub (bech32 encoded)
	if strings.HasPrefix(domainPart, "npub1") && len(domainPart) == 63 {
		return domainPart, nil
	}

	// Check if it's a subdomain-based hex pubkey
	hexPubkey := reconstructHexFromSubdomains(domainPart)
	if hexPubkey != "" {
		// Convert hex to npub
		if len(hexPubkey) != 64 || !isValidHex(hexPubkey) {
			return "", fmt.Errorf("invalid hex pubkey: %s", hexPubkey)
		}

		npub, err := nip19.EncodePublicKey(hexPubkey)
		if err != nil {
			return "", fmt.Errorf("failed to encode pubkey as npub: %w", err)
		}
		return npub, nil
	}

	return "", fmt.Errorf("could not extract npub from domain: %s", domain)
}

// reconstructHexFromSubdomains reconstructs a hex pubkey from subdomain format
func reconstructHexFromSubdomains(domainPart string) string {
	// Split by dots to get subdomains
	parts := strings.Split(domainPart, ".")

	// Concatenate all parts to form the hex string
	concatenated := strings.Join(parts, "")

	// Validate it's a valid 64-character hex string
	if len(concatenated) == 64 && isValidHex(concatenated) {
		// Validate each part is within DNS label length limit and is valid hex
		for _, part := range parts {
			if len(part) > 63 || !isValidHex(part) {
				return ""
			}
		}
		return strings.ToLower(concatenated)
	}

	return ""
}

// isValidHex checks if a string contains only hexadecimal characters
func isValidHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
