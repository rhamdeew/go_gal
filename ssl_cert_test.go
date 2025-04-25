package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSSLCertificateGeneration(t *testing.T) {
	// Create temporary files for testing
	certPath := filepath.Join(galleryDir, "test_ssl_cert.pem")
	keyPath := filepath.Join(galleryDir, "test_ssl_key.pem")

	// Clean up after tests
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	// Ensure gallery directory exists for tests
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		err = os.MkdirAll(galleryDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create gallery directory for tests: %v", err)
		}
	}

	// Generate SSL certificate
	err := generateSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Fatalf("SSL certificate not created at %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("SSL key not created at %s", keyPath)
	}

	// Read the certificate and verify its content
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	// Parse the certificate
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("Failed to parse certificate PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse X.509 certificate: %v", err)
	}

	// Validate certificate fields
	if cert.Subject.Organization[0] != "Go Crypto Gallery" {
		t.Errorf("Expected organization 'Go Crypto Gallery', got %s", cert.Subject.Organization[0])
	}

	if cert.Subject.CommonName != "localhost" {
		t.Errorf("Expected common name 'localhost', got %s", cert.Subject.CommonName)
	}

	// Verify certificate validity period
	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Errorf("Certificate not valid yet, NotBefore: %v", cert.NotBefore)
	}

	if cert.NotAfter.Before(now.AddDate(0, 11, 0)) { // Should be valid for at least 11 months
		t.Errorf("Certificate validity too short, NotAfter: %v", cert.NotAfter)
	}

	// Verify certificate has the correct DNS names and IP addresses
	found := false
	for _, dnsName := range cert.DNSNames {
		if dnsName == "localhost" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Certificate missing 'localhost' in DNS names")
	}

	// Verify 127.0.0.1 is included in IP addresses
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
			break
		}
	}
	if !foundIP {
		t.Error("Certificate missing '127.0.0.1' in IP addresses")
	}
}

func TestSSLCertificateRenewal(t *testing.T) {
	// Test that regenerating a certificate works even if the files already exist
	certPath := filepath.Join(galleryDir, "test_renewal_cert.pem")
	keyPath := filepath.Join(galleryDir, "test_renewal_key.pem")

	// Clean up after tests
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	// Generate certificate first time
	err := generateSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate (first): %v", err)
	}

	// Get modification time of first certificate
	firstCertInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Failed to stat first certificate: %v", err)
	}
	firstModTime := firstCertInfo.ModTime()

	// Wait a second to ensure different timestamps
	time.Sleep(1 * time.Second)

	// Generate certificate second time (renewal)
	err = generateSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate (renewal): %v", err)
	}

	// Get modification time of renewed certificate
	renewedCertInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Failed to stat renewed certificate: %v", err)
	}
	renewedModTime := renewedCertInfo.ModTime()

	// The renewed certificate should have a newer timestamp
	if !renewedModTime.After(firstModTime) {
		t.Errorf("Certificate renewal did not update file. First: %v, Renewed: %v",
			firstModTime, renewedModTime)
	}
}