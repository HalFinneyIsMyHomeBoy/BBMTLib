package certs

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
)

// TrustStore interface for managing system certificate trust stores
type TrustStore interface {
	AddCertificate(cert *x509.Certificate, domain string) error
	AddCertificatePEM(pemData, domain string) error
	AddCertificatePEMWithOptions(pemData, domain string, nonInteractive bool) error
	RemoveCertificate(domain string) error
	HasCertificate(domain string) (bool, error)
	ValidateCertificate(cert *x509.Certificate) error
	RequiresElevation() bool
}

// NewTrustStore creates a platform-specific trust store implementation
func NewTrustStore() TrustStore {
	switch runtime.GOOS {
	case "darwin":
		return &MacOSTrustStore{}
	case "linux":
		return &LinuxTrustStore{}
	case "windows":
		return &WindowsTrustStore{}
	default:
		logrus.Warn("Unsupported platform for certificate trust store, using generic implementation")
		return &GenericTrustStore{}
	}
}

// MacOSTrustStore manages certificates on macOS
type MacOSTrustStore struct {
	keychain string
}

func (m *MacOSTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
	// Convert x509.Certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return m.AddCertificatePEM(string(certPEM), domain)
}

func (m *MacOSTrustStore) AddCertificatePEM(pemData, domain string) error {
	return m.AddCertificatePEMWithOptions(pemData, domain, false)
}

func (m *MacOSTrustStore) AddCertificatePEMWithOptions(pemData, domain string, nonInteractive bool) error {
	// SECURITY LOG: Critical security operation
	logrus.Warnf("SECURITY CRITICAL: Adding certificate to macOS keychain for %s (non-interactive: %v)", domain, nonInteractive)

	// Create temporary certificate file with PEM data directly
	tempFile, err := writePEMToTempFile(pemData, domain)
	if err != nil {
		return fmt.Errorf("failed to write cert to temp file: %w", err)
	}
	defer os.Remove(tempFile)

	// Check if certificate already exists and is trusted
	if exists, _ := m.HasCertificate(domain); exists {
		if trusted, _ := m.isCertificateTrusted(domain); trusted {
			logrus.Infof("Certificate for %s already exists and is trusted, skipping", domain)
			return nil
		}
		logrus.Infof("Certificate for %s exists but not trusted, will update trust settings", domain)

		// Skip keychain addition, go directly to trust settings
		if err := m.setCertificateTrust(domain, nonInteractive); err != nil {
			logrus.Warnf("Trust settings failed for existing certificate: %v", err)
		}

		// Step 3: Flush certificate caches to ensure immediate effect
		m.flushCertificateCaches()

		logrus.Warnf("SECURITY CRITICAL: Successfully updated trust settings for existing certificate %s", domain)
		return nil
	}

	// Step 1: Add certificate to keychain (will handle "already exists" cases)
	if err := m.addCertificateToKeychain(tempFile, domain, nonInteractive); err != nil {
		return fmt.Errorf("failed to add certificate to keychain: %w", err)
	}

	// Step 2: Set trust settings for SSL
	if err := m.setCertificateTrust(domain, nonInteractive); err != nil {
		logrus.Warnf("Certificate added but trust settings failed: %v", err)
		// Don't return error - certificate is installed, just not explicitly trusted
		// Applications may still work depending on their trust validation
	}

	// Step 3: Flush certificate caches to ensure immediate effect
	m.flushCertificateCaches()

	logrus.Warnf("SECURITY CRITICAL: Successfully added and trusted certificate for %s", domain)
	return nil
}

// addCertificateToKeychain adds the certificate to the macOS keychain
func (m *MacOSTrustStore) addCertificateToKeychain(certFile, domain string, nonInteractive bool) error {
	// Try system keychain first (requires admin), then user keychain
	keychains := []struct {
		name       string
		keychain   string
		needsAdmin bool
	}{
		{"system", "/Library/Keychains/System.keychain", true},
		{"user", "", false}, // Empty string uses default user keychain
	}

	var lastErr error
	for _, kc := range keychains {
		logrus.Debugf("CERT_DIAG: Trying to add certificate to %s keychain for %s", kc.name, domain)

		var args []string
		if kc.keychain != "" {
			args = []string{"add-certificates", "-k", kc.keychain, certFile}
		} else {
			args = []string{"add-certificates", certFile}
		}

		cmd := exec.Command("security", args...)

		if nonInteractive {
			cmd.Env = append(cmd.Env,
				"SUDO_ASKPASS=/dev/null",
				"SSH_ASKPASS=/dev/null",
			)
		}

		if output, err := cmd.CombinedOutput(); err != nil {
			outputStr := string(output)

			// Check if certificate already exists (not an error) - various forms
			if strings.Contains(outputStr, "already exists in the keychain") ||
				strings.Contains(outputStr, "already exists") ||
				strings.Contains(outputStr, "already in default keychain") ||
				strings.Contains(outputStr, "duplicate") {
				logrus.Infof("Certificate for %s already exists in %s keychain", domain, kc.name)
				return nil
			}

			logrus.Warnf("CERT_DIAG: Failed to add to %s keychain: %v (output: %s)", kc.name, err, outputStr)
			lastErr = fmt.Errorf("failed to add to %s keychain: %w", kc.name, err)
			continue
		}

		logrus.Infof("Successfully added certificate for %s to %s keychain", domain, kc.name)
		return nil
	}

	return fmt.Errorf("failed to add certificate to any keychain: %w", lastErr)
}

// setCertificateTrust sets trust settings for the certificate
func (m *MacOSTrustStore) setCertificateTrust(domain string, nonInteractive bool) error {
	logrus.Debugf("CERT_DIAG: Setting trust settings for %s", domain)

	// Create a temporary certificate file from keychain
	tempFile, err := m.createTempCertFromKeychain(domain)
	if err != nil {
		return fmt.Errorf("failed to create temp cert file: %w", err)
	}
	defer os.Remove(tempFile)

	// Try add-trusted-cert to make the certificate trusted for SSL
	// This is the most direct way to set trust on macOS
	attempts := []struct {
		name     string
		keychain string
	}{
		{"system keychain", "/Library/Keychains/System.keychain"},
		{"user keychain", ""},
	}

	var lastErr error
	for _, attempt := range attempts {
		logrus.Debugf("CERT_DIAG: Trying add-trusted-cert with %s for %s", attempt.name, domain)

		var args []string
		if attempt.keychain != "" {
			args = []string{
				"add-trusted-cert",
				"-d",              // Add to admin cert store
				"-r", "trustRoot", // Set trust settings
				"-p", "ssl", // Policy (SSL)
				"-k", attempt.keychain,
				tempFile,
			}
		} else {
			args = []string{
				"add-trusted-cert",
				"-d",              // Add to admin cert store
				"-r", "trustRoot", // Set trust settings
				"-p", "ssl", // Policy (SSL)
				tempFile,
			}
		}

		cmd := exec.Command("security", args...)
		if nonInteractive {
			cmd.Env = append(cmd.Env,
				"SUDO_ASKPASS=/dev/null",
				"SSH_ASKPASS=/dev/null",
			)
		}

		if output, err := cmd.CombinedOutput(); err != nil {
			outputStr := string(output)

			// Check if already trusted (not an error)
			if strings.Contains(outputStr, "already exists") ||
				strings.Contains(outputStr, "duplicate") {
				logrus.Infof("Certificate for %s is already trusted in %s", domain, attempt.name)
				return nil
			}

			logrus.Warnf("CERT_DIAG: add-trusted-cert failed for %s: %v (output: %s)", attempt.name, err, outputStr)
			lastErr = fmt.Errorf("add-trusted-cert failed for %s: %w", attempt.name, err)
			continue
		}

		logrus.Infof("Successfully set trust settings for %s using %s", domain, attempt.name)
		return nil
	}

	return fmt.Errorf("all trust setting attempts failed: %w", lastErr)
}

// createTempCertFromKeychain exports certificate from keychain to temp file
func (m *MacOSTrustStore) createTempCertFromKeychain(domain string) (string, error) {
	// Try to find and export certificate in PEM format
	keychains := []string{
		"/Library/Keychains/System.keychain",
		"", // Default user keychain
	}

	var certData []byte
	var err error

	for _, keychain := range keychains {
		var cmd *exec.Cmd
		if keychain != "" {
			cmd = exec.Command("security", "find-certificate", "-c", domain, "-p", keychain)
		} else {
			cmd = exec.Command("security", "find-certificate", "-c", domain, "-p")
		}

		if certData, err = cmd.CombinedOutput(); err == nil {
			break
		}
	}

	if err != nil {
		return "", fmt.Errorf("certificate not found in any keychain: %w", err)
	}

	// Create temporary file
	tempFile, err := os.CreateTemp("", fmt.Sprintf("nostr-trust-%s-*.pem", domain))
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(certData); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

// getCertificateFingerprint gets the SHA-1 fingerprint of the certificate
func (m *MacOSTrustStore) getCertificateFingerprint(domain string) (string, error) {
	// Find certificate and get its fingerprint
	cmd := exec.Command("security", "find-certificate", "-c", domain, "-Z", "/Library/Keychains/System.keychain")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try user keychain
		cmd = exec.Command("security", "find-certificate", "-c", domain, "-Z")
		if output, err = cmd.CombinedOutput(); err != nil {
			return "", fmt.Errorf("certificate not found in keychain")
		}
	}

	// Parse fingerprint from output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "SHA-1 hash: ") {
			fingerprint := strings.TrimPrefix(line, "SHA-1 hash: ")
			fingerprint = strings.ReplaceAll(fingerprint, " ", "")
			return strings.ToUpper(fingerprint), nil
		}
	}

	return "", fmt.Errorf("could not parse certificate fingerprint")
}

// isCertificateTrusted checks if the certificate is already trusted for SSL
func (m *MacOSTrustStore) isCertificateTrusted(domain string) (bool, error) {
	// Use dump-trust-settings to check if certificate is trusted
	cmd := exec.Command("security", "dump-trust-settings", "-d")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If dump-trust-settings fails, assume not trusted
		return false, nil
	}

	// Look for the domain in trust settings output
	outputStr := string(output)
	return strings.Contains(outputStr, domain), nil
}

// flushCertificateCaches flushes macOS certificate caches for immediate effect
func (m *MacOSTrustStore) flushCertificateCaches() {
	logrus.Debugf("CERT_DIAG: Flushing certificate caches")

	// Flush various certificate caches
	cacheCommands := [][]string{
		{"dscacheutil", "-flushcache"},               // DNS cache
		{"sudo", "killall", "-HUP", "mDNSResponder"}, // mDNS responder
		{"sudo", "killall", "SecurityServer"},        // Security server
	}

	for _, cmdArgs := range cacheCommands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Env = append(cmd.Env, "SUDO_ASKPASS=/dev/null")
		if err := cmd.Run(); err != nil {
			logrus.Debugf("CERT_DIAG: Cache flush command failed (non-critical): %v", err)
		}
	}

	logrus.Debugf("CERT_DIAG: Certificate cache flush completed")
}

func (m *MacOSTrustStore) RemoveCertificate(domain string) error {
	logrus.Warnf("SECURITY: Removing certificate for %s from macOS keychain", domain)

	cmd := exec.Command("security", "delete-certificate", "-c", domain, "/Library/Keychains/System.keychain")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to remove certificate: %w (output: %s)", err, output)
	}

	logrus.Infof("Successfully removed certificate for %s", domain)
	return nil
}

func (m *MacOSTrustStore) HasCertificate(domain string) (bool, error) {
	// Check both system and user keychains
	keychains := []string{
		"/Library/Keychains/System.keychain",
		// User keychain path will be auto-detected by security command if not specified
	}

	for _, keychain := range keychains {
		var cmd *exec.Cmd
		if keychain != "" {
			cmd = exec.Command("security", "find-certificate", "-c", domain, keychain)
		} else {
			// Search default keychain (user keychain)
			cmd = exec.Command("security", "find-certificate", "-c", domain)
		}

		if err := cmd.Run(); err == nil {
			logrus.Debugf("Certificate for %s found in keychain", domain)
			return true, nil
		}
	}

	// Also try searching for the certificate by a more generic pattern
	cmd := exec.Command("security", "find-certificate", "-c", domain)
	if err := cmd.Run(); err == nil {
		logrus.Debugf("Certificate for %s found in default keychain", domain)
		return true, nil
	}

	return false, nil
}

func (m *MacOSTrustStore) ValidateCertificate(cert *x509.Certificate) error {
	// Basic validation
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("certificate has invalid date range")
	}
	return nil
}

func (m *MacOSTrustStore) RequiresElevation() bool {
	return true // Requires admin privileges
}

// LinuxTrustStore manages certificates on Linux
type LinuxTrustStore struct {
	certDir string
}

func (l *LinuxTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
	// Convert x509.Certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return l.AddCertificatePEM(string(certPEM), domain)
}

func (l *LinuxTrustStore) AddCertificatePEM(pemData, domain string) error {
	return l.AddCertificatePEMWithOptions(pemData, domain, false)
}

func (l *LinuxTrustStore) AddCertificatePEMWithOptions(pemData, domain string, nonInteractive bool) error {
	// SECURITY LOG: Critical security operation
	logrus.Warnf("SECURITY CRITICAL: Adding certificate to Linux CA store for %s (non-interactive: %v)", domain, nonInteractive)

	certDir := "/usr/local/share/ca-certificates"
	certPath := filepath.Join(certDir, fmt.Sprintf("nostr-%s.crt", domain))

	// Check if certificate already exists
	if exists, _ := l.HasCertificate(domain); exists {
		logrus.Infof("Certificate for %s already exists, skipping", domain)
		return nil
	}

	// Create certificate directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write PEM data directly to file
	if err := os.WriteFile(certPath, []byte(pemData), 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// DANGEROUS: Update CA certificates system-wide
	cmd := exec.Command("update-ca-certificates")

	// Set non-interactive environment if requested
	if nonInteractive {
		cmd.Env = append(cmd.Env,
			"DEBIAN_FRONTEND=noninteractive",
			"SUDO_ASKPASS=/dev/null",
		)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(certPath) // Cleanup on failure
		logrus.Errorf("SECURITY ERROR: Failed to update CA certificates: %v (output: %s)", err, output)
		return fmt.Errorf("update-ca-certificates failed: %w (output: %s)", err, output)
	}

	logrus.Warnf("SECURITY CRITICAL: Successfully added certificate for %s to Linux CA store", domain)
	return nil
}

func (l *LinuxTrustStore) RemoveCertificate(domain string) error {
	logrus.Warnf("SECURITY: Removing certificate for %s from Linux CA store", domain)

	certPath := filepath.Join("/usr/local/share/ca-certificates", fmt.Sprintf("nostr-%s.crt", domain))

	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove certificate file: %w", err)
	}

	// Update CA certificates
	cmd := exec.Command("update-ca-certificates")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("update-ca-certificates failed: %w (output: %s)", err, output)
	}

	logrus.Infof("Successfully removed certificate for %s", domain)
	return nil
}

func (l *LinuxTrustStore) HasCertificate(domain string) (bool, error) {
	certPath := filepath.Join("/usr/local/share/ca-certificates", fmt.Sprintf("nostr-%s.crt", domain))
	_, err := os.Stat(certPath)
	return err == nil, nil
}

func (l *LinuxTrustStore) ValidateCertificate(cert *x509.Certificate) error {
	// Basic validation
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("certificate has invalid date range")
	}
	return nil
}

func (l *LinuxTrustStore) RequiresElevation() bool {
	return true // Requires sudo
}

// WindowsTrustStore manages certificates on Windows
type WindowsTrustStore struct{}

func (w *WindowsTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
	// Convert x509.Certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return w.AddCertificatePEM(string(certPEM), domain)
}

func (w *WindowsTrustStore) AddCertificatePEM(pemData, domain string) error {
	return w.AddCertificatePEMWithOptions(pemData, domain, false)
}

func (w *WindowsTrustStore) AddCertificatePEMWithOptions(pemData, domain string, nonInteractive bool) error {
	// SECURITY LOG: Critical security operation
	logrus.Warnf("SECURITY CRITICAL: Adding certificate to Windows certificate store for %s (non-interactive: %v)", domain, nonInteractive)

	// Check if certificate already exists
	if exists, _ := w.HasCertificate(domain); exists {
		logrus.Infof("Certificate for %s already exists, skipping", domain)
		return nil
	}

	// Write PEM data to temp file
	tempFile, err := writePEMToTempFile(pemData, domain)
	if err != nil {
		return fmt.Errorf("failed to write cert to temp file: %w", err)
	}
	defer os.Remove(tempFile)

	// DANGEROUS: Import using PowerShell
	psCmd := fmt.Sprintf(
		`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root`,
		tempFile,
	)

	cmd := exec.Command("powershell", "-Command", psCmd)

	// Set non-interactive environment if requested
	if nonInteractive {
		cmd.Env = append(cmd.Env,
			"POWERSHELL_TELEMETRY_OPTOUT=1",
		)
	}

	if output, err := cmd.CombinedOutput(); err != nil {
		logrus.Errorf("SECURITY ERROR: Failed to import certificate: %v (output: %s)", err, output)
		return fmt.Errorf("powershell import failed: %w (output: %s)", err, output)
	}

	logrus.Warnf("SECURITY CRITICAL: Successfully added certificate for %s to Windows certificate store", domain)
	return nil
}

func (w *WindowsTrustStore) RemoveCertificate(domain string) error {
	logrus.Warnf("SECURITY: Removing certificate for %s from Windows certificate store", domain)

	psCmd := fmt.Sprintf(
		`Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*%s*"} | Remove-Item`,
		domain,
	)

	cmd := exec.Command("powershell", "-Command", psCmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell removal failed: %w (output: %s)", err, output)
	}

	logrus.Infof("Successfully removed certificate for %s", domain)
	return nil
}

func (w *WindowsTrustStore) HasCertificate(domain string) (bool, error) {
	// Query certificate store
	psCmd := fmt.Sprintf(
		`Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*%s*"}`,
		domain,
	)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}

	return len(strings.TrimSpace(string(output))) > 0, nil
}

func (w *WindowsTrustStore) ValidateCertificate(cert *x509.Certificate) error {
	// Basic validation
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("certificate has invalid date range")
	}
	return nil
}

func (w *WindowsTrustStore) RequiresElevation() bool {
	return true // Requires administrator privileges
}

// GenericTrustStore is a fallback implementation that doesn't actually install certificates
type GenericTrustStore struct{}

func (g *GenericTrustStore) AddCertificate(cert *x509.Certificate, domain string) error {
	logrus.Warnf("SECURITY WARNING: Generic trust store cannot install certificates for %s", domain)
	logrus.Warnf("Platform %s is not supported for automatic certificate installation", runtime.GOOS)
	return fmt.Errorf("certificate installation not supported on platform %s", runtime.GOOS)
}

func (g *GenericTrustStore) AddCertificatePEM(pemData, domain string) error {
	return g.AddCertificatePEMWithOptions(pemData, domain, false)
}

func (g *GenericTrustStore) AddCertificatePEMWithOptions(pemData, domain string, nonInteractive bool) error {
	logrus.Warnf("SECURITY WARNING: Generic trust store cannot install certificates for %s", domain)
	logrus.Warnf("Platform %s is not supported for automatic certificate installation", runtime.GOOS)
	return fmt.Errorf("certificate installation not supported on platform %s", runtime.GOOS)
}

func (g *GenericTrustStore) RemoveCertificate(domain string) error {
	return fmt.Errorf("certificate removal not supported on platform %s", runtime.GOOS)
}

func (g *GenericTrustStore) HasCertificate(domain string) (bool, error) {
	return false, nil
}

func (g *GenericTrustStore) ValidateCertificate(cert *x509.Certificate) error {
	// Basic validation
	if cert.NotAfter.Before(cert.NotBefore) {
		return fmt.Errorf("certificate has invalid date range")
	}
	return nil
}

func (g *GenericTrustStore) RequiresElevation() bool {
	return false
}

// Helper functions

func writeCertToTempFile(cert *x509.Certificate, domain string) (string, error) {
	tempFile, err := os.CreateTemp("", fmt.Sprintf("nostr-cert-%s-*.crt", domain))
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	if err := writeCertToFile(cert, tempFile.Name()); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

func writePEMToTempFile(pemData, domain string) (string, error) {
	tempFile, err := os.CreateTemp("", fmt.Sprintf("nostr-cert-%s-*.crt", domain))
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// COMPREHENSIVE DIAGNOSTIC LOGGING
	logrus.Debugf("CERT_DIAG: Writing PEM data for %s to %s", domain, tempFile.Name())
	logrus.Debugf("CERT_DIAG: Original length: %d chars", len(pemData))

	// Diagnose PEM format issues
	if err := diagnosePEMFormat(pemData, domain); err != nil {
		logrus.Errorf("CERT_DIAG: PEM format validation failed: %v", err)
		// Continue anyway to see what macOS reports
	}

	// Clean and validate PEM data
	cleanedPEM, err := cleanPEMData(pemData, domain)
	if err != nil {
		os.Remove(tempFile.Name())
		return "", fmt.Errorf("PEM cleaning failed: %w", err)
	}

	if _, err := tempFile.WriteString(cleanedPEM); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	// Post-write validation
	if err := validateWrittenFile(tempFile.Name(), domain); err != nil {
		logrus.Errorf("CERT_DIAG: File validation failed: %v", err)
	}

	logrus.Debugf("CERT_DIAG: Successfully wrote PEM file: %s", tempFile.Name())
	return tempFile.Name(), nil
}

// diagnosePEMFormat performs comprehensive PEM format validation
func diagnosePEMFormat(pemData, domain string) error {
	logrus.Debugf("CERT_DIAG: Diagnosing PEM format for %s", domain)

	// Check basic structure
	if len(pemData) == 0 {
		return fmt.Errorf("empty PEM data")
	}

	// Check for BOM
	if strings.HasPrefix(pemData, "\ufeff") {
		logrus.Warnf("CERT_DIAG: Found UTF-8 BOM in PEM data for %s", domain)
	}

	// Check for binary data (should not contain null bytes)
	if strings.Contains(pemData, "\x00") {
		return fmt.Errorf("PEM data contains null bytes (likely binary data)")
	}

	// Check PEM headers
	if !strings.Contains(pemData, "-----BEGIN") {
		return fmt.Errorf("missing PEM BEGIN header")
	}
	if !strings.Contains(pemData, "-----END") {
		return fmt.Errorf("missing PEM END header")
	}

	// Check for valid certificate header
	validHeaders := []string{
		"-----BEGIN CERTIFICATE-----",
		"-----BEGIN X509 CERTIFICATE-----",
		"-----BEGIN TRUSTED CERTIFICATE-----",
	}
	hasValidHeader := false
	for _, header := range validHeaders {
		if strings.Contains(pemData, header) {
			hasValidHeader = true
			logrus.Debugf("CERT_DIAG: Found valid header: %s", header)
			break
		}
	}
	if !hasValidHeader {
		return fmt.Errorf("no valid certificate header found")
	}

	// Check line endings
	if strings.Contains(pemData, "\r\n") {
		logrus.Warnf("CERT_DIAG: Found Windows line endings in PEM for %s", domain)
	}

	// Log first and last few lines for debugging
	lines := strings.Split(pemData, "\n")
	logrus.Debugf("CERT_DIAG: PEM has %d lines", len(lines))
	if len(lines) > 0 {
		logrus.Debugf("CERT_DIAG: First line: %q", lines[0])
		logrus.Debugf("CERT_DIAG: Last line: %q", lines[len(lines)-1])
	}

	return nil
}

// cleanPEMData cleans and normalizes PEM data
func cleanPEMData(pemData, domain string) (string, error) {
	logrus.Debugf("CERT_DIAG: Cleaning PEM data for %s", domain)

	// Remove BOM if present
	pemData = strings.TrimPrefix(pemData, "\ufeff")

	// Normalize line endings
	pemData = strings.ReplaceAll(pemData, "\r\n", "\n")
	pemData = strings.ReplaceAll(pemData, "\r", "\n")

	// Trim excessive whitespace
	pemData = strings.TrimSpace(pemData)

	// Ensure proper line ending
	if !strings.HasSuffix(pemData, "\n") {
		pemData += "\n"
		logrus.Debugf("CERT_DIAG: Added trailing newline")
	}

	// Validate that we can decode it
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", fmt.Errorf("PEM decoding failed after cleaning")
	}
	if block.Type != "CERTIFICATE" {
		logrus.Warnf("CERT_DIAG: PEM block type is %q, expected CERTIFICATE", block.Type)
	}

	logrus.Debugf("CERT_DIAG: Cleaned PEM length: %d chars", len(pemData))
	return pemData, nil
}

// validateWrittenFile validates the written certificate file
func validateWrittenFile(filePath, domain string) error {
	logrus.Debugf("CERT_DIAG: Validating written file %s for %s", filePath, domain)

	// Check file exists and is readable
	stat, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}

	logrus.Debugf("CERT_DIAG: File size: %d bytes, mode: %v", stat.Size(), stat.Mode())

	if stat.Size() == 0 {
		return fmt.Errorf("file is empty")
	}

	// Read back and validate
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("cannot read file: %w", err)
	}

	// Try to decode as PEM
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("file does not contain valid PEM data")
	}

	// Try to parse as X.509 certificate
	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("file does not contain valid X.509 certificate: %w", err)
	}

	logrus.Debugf("CERT_DIAG: File validation successful")
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func writeCertToFile(cert *x509.Certificate, path string) error {
	// Encode certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	return os.WriteFile(path, certPEM, 0644)
}
