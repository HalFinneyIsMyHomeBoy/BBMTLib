package dns

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nostr-dns/nodns-server/internal/certs"
	"github.com/nostr-dns/nodns-server/internal/config"
	"github.com/nostr-dns/nodns-server/internal/nostr"
	"github.com/sirupsen/logrus"
)

// Server represents the DNS server
type Server struct {
	config      *config.Config
	nostrClient *nostr.Client
	dnsServer   *dns.Server
	resolver    *Resolver
	certManager *certs.Manager
}

// NewServer creates a new DNS server
func NewServer(cfg *config.Config, nostrClient *nostr.Client) (*Server, error) {
	certManager := certs.NewManager(cfg)
	resolver := NewResolver(cfg, nostrClient, certManager)

	server := &Server{
		config:      cfg,
		nostrClient: nostrClient,
		resolver:    resolver,
		certManager: certManager,
	}

	// Create DNS server
	mux := dns.NewServeMux()
	mux.HandleFunc(".", server.handleDNSRequest)

	server.dnsServer = &dns.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", cfg.Port),
		Net:     "udp",
		Handler: mux,
	}

	return server, nil
}

// Start starts the DNS server
func (s *Server) Start() error {
	logrus.Infof("Starting DNS server on port %d", s.config.Port)

	go func() {
		if err := s.dnsServer.ListenAndServe(); err != nil {
			logrus.Fatalf("DNS server failed: %v", err)
		}
	}()

	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	logrus.Info("Stopping DNS server")
	return s.dnsServer.Shutdown()
}

// handleDNSRequest handles incoming DNS requests
func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := &dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = false

	// Get the first question
	if len(r.Question) == 0 {
		logrus.Warn("DNS request with no questions")
		msg.SetRcode(r, dns.RcodeFormatError)
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	domain := strings.ToLower(question.Name)
	qtype := question.Qtype

	// Remove trailing dot
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}

	logrus.Infof("DNS query: %s (type: %s)", domain, dns.TypeToString[qtype])

	// Handle based on domain type
	if s.isNostrDomain(domain) {
		s.handleNostrDomain(w, r, msg, domain, qtype)
	} else {
		s.forwardToUpstream(w, r, msg, domain, qtype)
	}
}

// isNostrDomain checks if a domain should be handled by Nostr resolution
func (s *Server) isNostrDomain(domain string) bool {
	// Check for .nostr domains or other configured TLDs
	return strings.HasSuffix(domain, ".nostr") ||
		strings.HasSuffix(domain, ".net") && s.looksLikeNostrDomain(domain)
}

// looksLikeNostrDomain checks if a domain looks like a Nostr domain
func (s *Server) looksLikeNostrDomain(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	// Take everything except the TLD
	domainPart := strings.Join(parts[:len(parts)-1], ".")

	// Check if it starts with npub1 or could be hex subdomains
	return strings.HasPrefix(domainPart, "npub1") || s.couldBeHexSubdomains(domainPart)
}

// couldBeHexSubdomains checks if domain parts could represent hex subdomains
func (s *Server) couldBeHexSubdomains(domainPart string) bool {
	parts := strings.Split(domainPart, ".")

	// Check if all parts are hex and could combine to 64 chars
	totalLength := 0
	for _, part := range parts {
		if len(part) > 63 || len(part) == 0 {
			return false
		}
		if !s.isHex(part) {
			return false
		}
		totalLength += len(part)
	}

	return totalLength == 64
}

// isHex checks if string contains only hex characters
func (s *Server) isHex(str string) bool {
	for _, r := range str {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// handleNostrDomain handles DNS queries for Nostr domains
func (s *Server) handleNostrDomain(w dns.ResponseWriter, r *dns.Msg, msg *dns.Msg, domain string, qtype uint16) {
	logrus.Debugf("Handling Nostr domain: %s", domain)

	// Resolve using our resolver
	records, err := s.resolver.ResolveNostrDomain(domain, qtype)
	if err != nil {
		logrus.Warnf("Failed to resolve Nostr domain %s: %v", domain, err)
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	if len(records) == 0 {
		logrus.Debugf("No records found for %s", domain)
		msg.SetRcode(r, dns.RcodeNameError)
		w.WriteMsg(msg)
		return
	}

	// Add records to response
	for _, record := range records {
		msg.Answer = append(msg.Answer, record)
	}

	// Set response flags
	msg.Authoritative = true
	msg.RecursionAvailable = false

	logrus.Infof("Resolved %s to %d records", domain, len(records))

	// Debug: Log the message details before sending
	logrus.Debugf("Sending DNS response: %d answers, authoritative=%v", len(msg.Answer), msg.Authoritative)

	err = w.WriteMsg(msg)
	if err != nil {
		logrus.Errorf("Failed to write DNS response: %v", err)
	} else {
		logrus.Debugf("DNS response sent successfully")
	}
}

// forwardToUpstream forwards DNS queries to upstream servers
func (s *Server) forwardToUpstream(w dns.ResponseWriter, r *dns.Msg, msg *dns.Msg, domain string, qtype uint16) {
	logrus.Debugf("Forwarding %s to upstream DNS", domain)

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	var lastErr error

	// Try each upstream server
	for _, upstreamAddr := range s.config.ForwardDNS {
		resp, _, err := client.Exchange(r, upstreamAddr+":53")
		if err != nil {
			logrus.Warnf("Failed to query upstream %s: %v", upstreamAddr, err)
			lastErr = err
			continue
		}

		// Forward the response
		logrus.Debugf("Forwarded %s successfully via %s", domain, upstreamAddr)
		w.WriteMsg(resp)
		return
	}

	// All upstreams failed
	logrus.Errorf("All upstream DNS servers failed for %s: %v", domain, lastErr)
	msg.SetRcode(r, dns.RcodeServerFailure)
	w.WriteMsg(msg)
}

// Resolver handles the actual resolution logic
type Resolver struct {
	config      *config.Config
	nostrClient *nostr.Client
	certManager *certs.Manager
}

// NewResolver creates a new resolver
func NewResolver(cfg *config.Config, nostrClient *nostr.Client, certManager *certs.Manager) *Resolver {
	return &Resolver{
		config:      cfg,
		nostrClient: nostrClient,
		certManager: certManager,
	}
}

// ResolveNostrDomain resolves a Nostr domain to DNS records
func (r *Resolver) ResolveNostrDomain(domain string, qtype uint16) ([]dns.RR, error) {
	// Extract npub from domain
	npub, err := nostr.ExtractNpubFromDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to extract npub from domain: %w", err)
	}

	// Convert npub to pubkey
	pubkey, err := nostr.ConvertNpubToPubkey(npub)
	if err != nil {
		return nil, fmt.Errorf("failed to convert npub to pubkey: %w", err)
	}

	logrus.Debugf("Resolved domain %s to pubkey %s", domain, pubkey)

	// Fetch events from Nostr
	bundle, err := r.nostrClient.FetchEventsForPubkey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Nostr events: %w", err)
	}

	// Parse DNS records
	dnsRecords, err := r.nostrClient.ParseDNSRecords(bundle.DNSRecords)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS records: %w", err)
	}

	// Handle certificates if enabled and found
	if r.config.IsCertificateEnabled() && len(bundle.Certificates) > 0 {
		certificates, err := r.nostrClient.ParseCertificates(bundle.Certificates)
		if err != nil {
			logrus.Warnf("Failed to parse certificates: %v", err)
		} else {
			// Process certificates through the certificate manager
			r.certManager.ProcessCertificates(certificates, domain)
		}
	}

	// Convert to DNS response records and add signature TXT records
	return r.convertToDNSRecordsWithSignature(domain, dnsRecords, bundle.DNSRecords, qtype)
}

// convertToDNSRecords converts our DNSRecord structs to dns.RR
func (r *Resolver) convertToDNSRecords(domain string, records []*nostr.DNSRecord, qtype uint16) ([]dns.RR, error) {
	var result []dns.RR

	for _, record := range records {
		// Filter by query type if specified
		if qtype != dns.TypeANY && !r.matchesQueryType(record.Type, qtype) {
			continue
		}

		// Convert record based on type
		rr, err := r.convertSingleRecord(domain, record)
		if err != nil {
			logrus.Warnf("Failed to convert record: %v", err)
			continue
		}

		if rr != nil {
			result = append(result, rr)
		}
	}

	return result, nil
}

// convertToDNSRecordsWithSignature converts DNSRecord structs to dns.RR and adds signature TXT record
func (r *Resolver) convertToDNSRecordsWithSignature(domain string, records []*nostr.DNSRecord, event *gonostr.Event, qtype uint16) ([]dns.RR, error) {
	var result []dns.RR

	for _, record := range records {
		// Filter by query type if specified
		if qtype != dns.TypeANY && !r.matchesQueryType(record.Type, qtype) {
			continue
		}

		// Convert record based on type
		rr, err := r.convertSingleRecord(domain, record)
		if err != nil {
			logrus.Warnf("Failed to convert record: %v", err)
			continue
		}

		if rr != nil {
			result = append(result, rr)
		}
	}

	// Add signature and created_at as one TXT record if TXT records are being queried
	if qtype == dns.TypeANY || qtype == dns.TypeTXT {
		// Add signature TXT record with both sig and created_at
		metadataRecord := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   domain + ".",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Txt: []string{fmt.Sprintf("sig=%s created_at=%d", event.Sig, event.CreatedAt)},
		}
		result = append(result, metadataRecord)
	}

	return result, nil
}

// matchesQueryType checks if a record type matches the DNS query type
func (r *Resolver) matchesQueryType(recordType string, qtype uint16) bool {
	switch recordType {
	case "A":
		return qtype == dns.TypeA
	case "AAAA":
		return qtype == dns.TypeAAAA
	case "CNAME":
		return qtype == dns.TypeCNAME
	case "TXT":
		return qtype == dns.TypeTXT
	case "MX":
		return qtype == dns.TypeMX
	case "NS":
		return qtype == dns.TypeNS
	case "SRV":
		return qtype == dns.TypeSRV
	case "PTR":
		return qtype == dns.TypePTR
	default:
		return false
	}
}

// convertSingleRecord converts a single DNSRecord to dns.RR
func (r *Resolver) convertSingleRecord(domain string, record *nostr.DNSRecord) (dns.RR, error) {
	// Determine the record name
	name := domain
	if record.Name != "@" && record.Name != "" {
		name = record.Name + "." + domain
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Create header
	header := dns.RR_Header{
		Name:   name,
		Rrtype: r.getRecordType(record.Type),
		Class:  dns.ClassINET,
		Ttl:    record.TTL,
	}

	// Create specific record types
	switch record.Type {
	case "A":
		ip := net.ParseIP(record.Data[0])
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %s", record.Data[0])
		}
		return &dns.A{
			Hdr: header,
			A:   ip.To4(),
		}, nil

	case "AAAA":
		ip := net.ParseIP(record.Data[0])
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", record.Data[0])
		}
		return &dns.AAAA{
			Hdr:  header,
			AAAA: ip,
		}, nil

	case "CNAME":
		target := record.Data[0]
		if !strings.HasSuffix(target, ".") {
			target += "."
		}
		return &dns.CNAME{
			Hdr:    header,
			Target: target,
		}, nil

	case "TXT":
		return &dns.TXT{
			Hdr: header,
			Txt: []string{record.Data[0]},
		}, nil

	case "MX":
		priority, err := strconv.ParseUint(record.Data[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid MX priority: %s", record.Data[0])
		}
		mx := record.Data[1]
		if !strings.HasSuffix(mx, ".") {
			mx += "."
		}
		return &dns.MX{
			Hdr:        header,
			Preference: uint16(priority),
			Mx:         mx,
		}, nil

	case "NS":
		ns := record.Data[0]
		if !strings.HasSuffix(ns, ".") {
			ns += "."
		}
		return &dns.NS{
			Hdr: header,
			Ns:  ns,
		}, nil

	case "SRV":
		priority, _ := strconv.ParseUint(record.Data[0], 10, 16)
		weight, _ := strconv.ParseUint(record.Data[1], 10, 16)
		port, _ := strconv.ParseUint(record.Data[2], 10, 16)
		target := record.Data[3]
		if !strings.HasSuffix(target, ".") {
			target += "."
		}
		return &dns.SRV{
			Hdr:      header,
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   target,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported record type: %s", record.Type)
	}
}

// getRecordType converts string record type to DNS type constant
func (r *Resolver) getRecordType(recordType string) uint16 {
	switch recordType {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "TXT":
		return dns.TypeTXT
	case "MX":
		return dns.TypeMX
	case "NS":
		return dns.TypeNS
	case "SRV":
		return dns.TypeSRV
	case "PTR":
		return dns.TypePTR
	default:
		return dns.TypeNone
	}
}

// handleCertificates processes certificates (placeholder for now)
func (r *Resolver) handleCertificates(certificates []*nostr.Certificate, domain string) {
	logrus.Infof("SECURITY: Found %d certificates for domain %s", len(certificates), domain)

	for _, cert := range certificates {
		logrus.Infof("SECURITY: Certificate for TLD %s (expires: %s, fingerprint: %s)",
			cert.TLD, cert.Expiry.Format("2006-01-02"), cert.Fingerprint)
	}

	// TODO: Implement certificate trust store integration
	if r.config.Certificates.AutoInstall {
		logrus.Warn("SECURITY WARNING: Auto-install is enabled but not yet implemented")
	}
}
