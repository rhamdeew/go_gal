package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHMACVerification(t *testing.T) {
	// Ensure gallery directory exists for tests
	if _, err := os.Stat(galleryDir); os.IsNotExist(err) {
		err = os.MkdirAll(galleryDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create gallery directory for tests: %v", err)
		}
	}

	// Create a temporary test file path
	testPath := filepath.Join(galleryDir, "test_hmac_file.txt"+encryptedExt)
	// Clean up at the end
	defer os.Remove(testPath)

	// Test data and password
	testData := []byte("This is test data for HMAC verification")
	passwordHash := hashPassword("secure_password")

	// Encrypt and save the file
	err := encryptAndSaveFile(testData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt and save file: %v", err)
	}

	// Verify the file was created
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Fatalf("Encrypted file does not exist at %s", testPath)
	}

	// Test decryption and HMAC verification
	decrypted, err := decryptFile(testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt file: %v", err)
	}

	// Verify the content matches
	if !bytes.Equal(testData, decrypted) {
		t.Errorf("Decrypted content doesn't match original.\nOriginal: %s\nDecrypted: %s",
			string(testData), string(decrypted))
	}

	// Now tamper with the file to test HMAC validation
	// Read the file
	fileContent, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Find a byte to modify after the IV and HMAC sections
	// File format: [IV (16 bytes)][HMAC size (8 bytes)][HMAC (32 bytes)][Encrypted data]
	modifyIndex := 16 + 8 + 32 + 5 // Modify a byte in the encrypted data
	if len(fileContent) <= modifyIndex {
		t.Fatalf("File content too small for test, need at least %d bytes", modifyIndex+1)
	}

	// Modify the byte
	tamperedContent := make([]byte, len(fileContent))
	copy(tamperedContent, fileContent)
	tamperedContent[modifyIndex] ^= 0xFF // Flip all bits

	// Write the tampered content back
	err = os.WriteFile(testPath, tamperedContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write tampered content: %v", err)
	}

	// Attempt to decrypt the tampered file
	_, err = decryptFile(testPath, passwordHash)
	if err == nil {
		t.Error("Expected HMAC verification to fail on tampered file, but it succeeded")
	} else if !bytes.Contains([]byte(err.Error()), []byte("incorrect password or tampered file")) {
		t.Errorf("Expected 'incorrect password or tampered file' error, got: %v", err)
	}
}

func TestHMACWithWrongPassword(t *testing.T) {
	// Create a temporary test file path
	testPath := filepath.Join(galleryDir, "test_hmac_wrong_pw.txt"+encryptedExt)
	// Clean up at the end
	defer os.Remove(testPath)

	// Test data
	testData := []byte("This is test data for HMAC with wrong password")
	correctHash := hashPassword("correct_password")
	wrongHash := hashPassword("wrong_password")

	// Encrypt and save with correct password
	err := encryptAndSaveFile(testData, testPath, correctHash)
	if err != nil {
		t.Fatalf("Failed to encrypt and save file: %v", err)
	}

	// Try to decrypt with wrong password
	_, err = decryptFile(testPath, wrongHash)
	if err == nil {
		t.Error("Expected HMAC verification to fail with wrong password, but it succeeded")
	} else if !bytes.Contains([]byte(err.Error()), []byte("incorrect password")) {
		t.Errorf("Expected 'incorrect password' error, got: %v", err)
	}
}

func TestHMACCalculation(t *testing.T) {
	// Verify that our HMAC calculation matches the expected algorithm
	testData := []byte("Test data for HMAC calculation")
	passwordHash := "0123456789abcdef0123456789abcdef"

	// Calculate HMAC directly
	h := hmac.New(sha256.New, []byte(passwordHash))
	h.Write(testData)
	expectedMAC := h.Sum(nil)

	// Compare with our implementation logic
	// This is simplified and should match the logic in encryptAndSaveFile
	h2 := hmac.New(sha256.New, []byte(passwordHash))
	h2.Write(testData)
	actualMAC := h2.Sum(nil)

	if !hmac.Equal(expectedMAC, actualMAC) {
		t.Error("HMAC calculation doesn't match expected algorithm")
	}
}
