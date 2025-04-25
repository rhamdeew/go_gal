package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptFileNameDecryptFileName(t *testing.T) {
	// Ensure gallery directory exists for tests
	galleryPath := filepath.Join(".", galleryDir)
	if _, err := os.Stat(galleryPath); os.IsNotExist(err) {
		err = os.MkdirAll(galleryPath, 0755)
		if err != nil {
			t.Fatalf("Failed to create gallery directory for tests: %v", err)
		}
	}

	testCases := []struct {
		name     string
		filename string
		password string
	}{
		{
			name:     "Simple filename",
			filename: "test.jpg",
			password: "password123",
		},
		{
			name:     "Complex filename with special characters",
			filename: "My Family Vacation (2023) - Day 1!.jpg",
			password: "complex!P@$$w0rd",
		},
		{
			name:     "Unicode filename",
			filename: "фотография.jpg",
			password: "password123",
		},
		{
			name:     "Path-like filename",
			filename: "vacation/beach/sunset.jpg",
			password: "password123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create password hash
			passwordHash := hashPassword(tc.password)

			// Encrypt the filename
			encryptedName, err := encryptFileName(tc.filename, passwordHash)
			if err != nil {
				t.Fatalf("Failed to encrypt filename: %v", err)
			}

			// Verify the encrypted name is not the same as the original
			if encryptedName == tc.filename {
				t.Errorf("Encrypted filename is same as original: %s", encryptedName)
			}

			// Decrypt the filename
			decryptedName, err := decryptFileName(encryptedName, passwordHash)
			if err != nil {
				t.Fatalf("Failed to decrypt filename: %v", err)
			}

			// Verify the decrypted name matches the original
			if decryptedName != tc.filename {
				t.Errorf("Decrypted filename doesn't match original.\nOriginal: %s\nDecrypted: %s",
					tc.filename, decryptedName)
			}

			// Test with incorrect password
			wrongHash := hashPassword("wrong" + tc.password)
			_, err = decryptFileName(encryptedName, wrongHash)
			if err == nil {
				t.Error("Expected error when decrypting with wrong password, but got none")
			} else if !strings.Contains(err.Error(), "incorrect password") {
				t.Errorf("Expected 'incorrect password' error, got: %v", err)
			}
		})
	}
}

func TestEncryptFileNameEdgeCases(t *testing.T) {
	// Test with empty filename
	passwordHash := hashPassword("password123")

	// Empty filename should still work
	encryptedEmpty, err := encryptFileName("", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt empty filename: %v", err)
	}

	decryptedEmpty, err := decryptFileName(encryptedEmpty, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt empty filename: %v", err)
	}

	if decryptedEmpty != "" {
		t.Errorf("Decrypted empty filename is not empty: %s", decryptedEmpty)
	}

	// Test with very long filename
	longName := string(make([]byte, 1000))
	for i := range longName {
		longName = longName[:i] + "a" + longName[i+1:]
	}

	encryptedLong, err := encryptFileName(longName, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt long filename: %v", err)
	}

	decryptedLong, err := decryptFileName(encryptedLong, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt long filename: %v", err)
	}

	if decryptedLong != longName {
		t.Errorf("Decrypted long filename doesn't match original")
	}
}

func TestValidationTagVerification(t *testing.T) {
	// Test the validation tag verification logic
	passwordHash := hashPassword("secure_password")

	// Encrypt a filename
	filename := "test_validation.jpg"
	encryptedName, err := encryptFileName(filename, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	// Corrupt the encrypted data by changing the last few characters
	// This should corrupt the validation tag
	corruptedName := encryptedName[:len(encryptedName)-4] + "abcd"

	// Decryption should fail with a validation error
	_, err = decryptFileName(corruptedName, passwordHash)
	if err == nil {
		t.Error("Expected validation error with corrupted data, got none")
	} else if !strings.Contains(err.Error(), "incorrect password") {
		t.Errorf("Expected 'incorrect password' error, got: %v", err)
	}
}

func TestDecryptWithInvalidHex(t *testing.T) {
	// Test decryption with invalid hex string
	invalidHex := "not a hex string"
	passwordHash := hashPassword("password")

	_, err := decryptFileName(invalidHex, passwordHash)
	if err == nil {
		t.Error("Expected error when decrypting invalid hex, but got none")
	}
}

func TestShortEncryptedData(t *testing.T) {
	// Test decryption with data that's too short to include the validation tag
	shortHex := "abcd" // Just a few bytes
	passwordHash := hashPassword("password")

	_, err := decryptFileName(shortHex, passwordHash)
	if err == nil {
		t.Error("Expected error when decrypting too-short data, but got none")
	} else if !strings.Contains(err.Error(), "too short") {
		t.Errorf("Expected 'too short' error, got: %v", err)
	}
}