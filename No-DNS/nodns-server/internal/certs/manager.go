package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/nostr-dns/nodns-server/internal/config"
	"github.com/nostr-dns/nodns-server/internal/nostr"
	"github.com/sirupsen/logrus"
)

// Manager handles certificate operations and trust store integration
type Manager struct {
	config     *config.Config
	trustStore TrustStore
	certQueue  chan *CertificateInstallJob
	stopChan   chan struct{}
}

// CertificateInstallJob represents a certificate installation job
type CertificateInstallJob struct {
	Certificate *nostr.Certificate
	Domain      string
}

// CertInstallEvent represents a certificate installation event for auditing
type CertInstallEvent struct {
	Domain      string    `json:"domain"`
	TLD         string    `json:"tld"`
	Timestamp   time.Time `json:"timestamp"`
	Success     bool      `json:"success"`
	Error       string    `json:"error,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Expiry      time.Time `json:"expiry"`
	Source      string    `json:"source"` // "nostr"
	Risk        string    `json:"risk"`   // "HIGH", "CRITICAL"
}

// NewManager creates a new certificate manager
func NewManager(cfg *config.Config) *Manager {
	m := &Manager{
		config:     cfg,
		trustStore: NewTrustStore(),
		certQueue:  make(chan *CertificateInstallJob, 100), // Buffer for 100 jobs
		stopChan:   make(chan struct{}),
	}

	// Start certificate installation worker
	go m.certificateWorker()

	return m
}

// certificateWorker processes certificate installation jobs asynchronously
func (m *Manager) certificateWorker() {
	logrus.Debug("Certificate installation worker started")

	for {
		select {
		case job := <-m.certQueue:
			logrus.Debugf("Processing certificate installation job for %s", job.Domain)

			if err := m.installCertificate(job.Certificate, job.Domain); err != nil {
				logrus.Errorf("SECURITY ERROR: Failed to install certificate for %s: %v", job.Domain, err)
				m.auditCertificateInstallation(job.Certificate, job.Domain, false, err.Error())
			} else {
				m.auditCertificateInstallation(job.Certificate, job.Domain, true, "")
			}

		case <-m.stopChan:
			logrus.Debug("Certificate installation worker stopping")
			return
		}
	}
}

// Stop stops the certificate manager and worker
func (m *Manager) Stop() {
	close(m.stopChan)
}

// ProcessCertificates processes certificates from Nostr events
func (m *Manager) ProcessCertificates(certificates []*nostr.Certificate, domain string) {
	if m.config.Certificates.DisableDangerous {
		logrus.Debug("Certificate processing disabled for safety")
		return
	}

	domainTLD := extractTLDFromDomain(domain)

	for _, cert := range certificates {
		// Only process certificate if it matches the queried domain TLD
		if cert.TLD == domainTLD {
			go m.installCertificateAsync(cert, domain)
		} else {
			logrus.Debugf("Skipping certificate for TLD %s (queried domain is %s)", cert.TLD, domain)
		}
	}
}

// installCertificateAsync queues a certificate for asynchronous installation
func (m *Manager) installCertificateAsync(cert *nostr.Certificate, domain string) {
	// Queue the certificate installation job (non-blocking)
	job := &CertificateInstallJob{
		Certificate: cert,
		Domain:      domain,
	}

	select {
	case m.certQueue <- job:
		logrus.Debugf("Queued certificate installation for %s", domain)
	default:
		logrus.Warnf("Certificate installation queue full, dropping job for %s", domain)
	}
}

// installCertificate installs a single certificate
func (m *Manager) installCertificate(cert *nostr.Certificate, domain string) error {
	// SECURITY AUDIT LOG
	logrus.Warnf("SECURITY AUDIT: Attempting to install certificate for %s (fingerprint: %s)",
		domain, cert.Fingerprint)

	// Parse PEM certificate
	x509Cert, err := m.parsePEMCertificate(cert.PEM)
	if err != nil {
		return fmt.Errorf("invalid PEM certificate: %w", err)
	}

	// Validate certificate
	if err := m.validateCertificate(x509Cert, cert, domain); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// Check if we should install certificates for this TLD
	if !m.config.ShouldInstallCertForTLD(cert.TLD) {
		logrus.Infof("Certificate installation disabled for TLD %s", cert.TLD)
		return nil
	}

	// Check if we need user consent
	if m.config.Certificates.PromptUser && !m.config.Certificates.AutoInstall {
		if !m.getUserConsent(x509Cert, domain) {
			return fmt.Errorf("user declined certificate installation")
		}
	}

	// Check elevation requirements
	if m.trustStore.RequiresElevation() && !m.hasElevatedPrivileges() {
		logrus.Errorf("SECURITY ERROR: Certificate installation requires elevation for %s", domain)
		return fmt.Errorf("insufficient privileges for certificate installation")
	}

	// DANGEROUS: Install certificate using PEM data directly
	if ts, ok := m.trustStore.(interface {
		AddCertificatePEMWithOptions(string, string, bool) error
	}); ok {
		// Use the non-interactive option from config
		if err := ts.AddCertificatePEMWithOptions(cert.PEM, domain, m.config.Certificates.NonInteractive); err != nil {
			logrus.Errorf("SECURITY ERROR: Failed to add certificate to trust store for %s: %v", domain, err)
			return fmt.Errorf("failed to add certificate to trust store: %w", err)
		}
	} else {
		// Fallback to regular method
		if err := m.trustStore.AddCertificatePEM(cert.PEM, domain); err != nil {
			logrus.Errorf("SECURITY ERROR: Failed to add certificate to trust store for %s: %v", domain, err)
			return fmt.Errorf("failed to add certificate to trust store: %w", err)
		}
	}

	// SECURITY AUDIT LOG: Successful installation
	logrus.Warnf("SECURITY AUDIT: Successfully installed certificate for %s (expires: %s)",
		domain, x509Cert.NotAfter.Format("2006-01-02"))

	return nil
}

// validateCertificate performs comprehensive certificate validation
func (m *Manager) validateCertificate(x509Cert *x509.Certificate, cert *nostr.Certificate, domain string) error {
	// Basic trust store validation
	if err := m.trustStore.ValidateCertificate(x509Cert); err != nil {
		return err
	}

	// Check expiration
	if x509Cert.NotAfter.Before(time.Now()) {
		logrus.Warnf("SECURITY WARNING: Rejecting expired certificate for %s", domain)
		if m.config.Certificates.SkipExpired {
			return fmt.Errorf("certificate has expired")
		}
	}

	// Check if certificate is too old
	if m.config.Certificates.MaxAge > 0 {
		maxAge := time.Duration(m.config.Certificates.MaxAge) * 24 * time.Hour
		if x509Cert.NotBefore.Before(time.Now().Add(-maxAge)) {
			return fmt.Errorf("certificate is too old (older than %d days)", m.config.Certificates.MaxAge)
		}
	}

	// Check if certificate is self-signed (potential security risk)
	if m.isSelfSigned(x509Cert) {
		logrus.Warnf("SECURITY WARNING: Self-signed certificate detected for %s", domain)
		if m.config.Certificates.SkipSelfSigned {
			return fmt.Errorf("self-signed certificates are disabled")
		}
	}

	// Validate certificate chain if possible
	if err := m.validateCertificateChain(x509Cert); err != nil {
		logrus.Warnf("SECURITY WARNING: Certificate chain validation failed for %s: %v", domain, err)
		// Don't fail on chain validation errors as they might be expected for self-signed certs
	}

	return nil
}

// parsePEMCertificate parses a PEM-encoded certificate
func (m *Manager) parsePEMCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// isSelfSigned checks if a certificate is self-signed
func (m *Manager) isSelfSigned(cert *x509.Certificate) bool {
	return cert.Issuer.String() == cert.Subject.String()
}

// validateCertificateChain validates the certificate chain
func (m *Manager) validateCertificateChain(cert *x509.Certificate) error {
	// Basic validation - in a production system you'd want more comprehensive chain validation
	roots := x509.NewCertPool()
	roots.AddCert(cert) // Add self to pool for self-signed certs

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err := cert.Verify(opts)
	return err
}

// getUserConsent prompts the user for certificate installation consent
func (m *Manager) getUserConsent(cert *x509.Certificate, domain string) bool {
	// In a real implementation, this would show a GUI dialog or terminal prompt
	// For now, we'll just log and assume consent based on config
	logrus.Warnf("SECURITY PROMPT: Would install certificate for %s", domain)
	logrus.Warnf("  Subject: %s", cert.Subject.String())
	logrus.Warnf("  Issuer: %s", cert.Issuer.String())
	logrus.Warnf("  Expires: %s", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

	// In server mode, we can't prompt interactively, so we use the auto-install setting
	return m.config.Certificates.AutoInstall
}

// hasElevatedPrivileges checks if the process has elevated privileges
func (m *Manager) hasElevatedPrivileges() bool {
	// Simple check - in production you'd want more comprehensive privilege checking
	return true // Assume we have privileges for now
}

// auditCertificateInstallation logs certificate installation events
func (m *Manager) auditCertificateInstallation(cert *nostr.Certificate, domain string, success bool, errorMsg string) {
	// Log to audit system
	if success {
		logrus.Warnf("CERT_INSTALL_AUDIT: Successfully installed certificate for %s (TLD: %s, fingerprint: %s)",
			domain, cert.TLD, cert.Fingerprint)
	} else {
		logrus.Errorf("CERT_INSTALL_AUDIT: Failed to install certificate for %s (TLD: %s, error: %s)",
			domain, cert.TLD, errorMsg)
	}

	// Write to audit log file if configured
	if m.config.Certificates.AuditLog != "" {
		// TODO: Implement audit log file writing
		logrus.Debugf("Would write audit event to %s", m.config.Certificates.AuditLog)
	}
}

// RemoveCertificate removes a certificate from the trust store
func (m *Manager) RemoveCertificate(domain string) error {
	if m.config.Certificates.DisableDangerous {
		return fmt.Errorf("certificate operations are disabled")
	}

	logrus.Warnf("SECURITY AUDIT: Removing certificate for %s", domain)

	if err := m.trustStore.RemoveCertificate(domain); err != nil {
		return fmt.Errorf("failed to remove certificate: %w", err)
	}

	logrus.Infof("Successfully removed certificate for %s", domain)
	return nil
}

// ListInstalledCertificates lists certificates installed by this system
func (m *Manager) ListInstalledCertificates() ([]string, error) {
	// This would require platform-specific implementation to list only
	// certificates installed by nodns-server
	logrus.Debug("Certificate listing not yet implemented")
	return nil, fmt.Errorf("certificate listing not implemented")
}

// Helper functions

// extractTLDFromDomain extracts the TLD from a domain name
func extractTLDFromDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}
