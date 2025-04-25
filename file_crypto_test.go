package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptAndSaveFileFunctions(t *testing.T) {
	// Create a temporary test file path
	testPath := filepath.Join(galleryDir, "test_encrypt_file.txt"+encryptedExt)

	// Generate a test password hash
	passwordHash := hashPassword("testpassword")

	// Test data
	testData := []byte("This is test data for file encryption and decryption")

	// Test encryptAndSaveFile
	err := encryptAndSaveFile(testData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt and save file: %v", err)
	}
	defer os.Remove(testPath)

	// Verify the file exists
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Fatalf("Encrypted file does not exist at %s", testPath)
	}

	// Test decryptFile
	decrypted, err := decryptFile(testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt file: %v", err)
	}

	// Verify the decrypted content
	if !bytes.Equal(testData, decrypted) {
		t.Errorf("Decrypted data does not match original data.\nOriginal: %s\nDecrypted: %s",
			string(testData), string(decrypted))
	}

	// Test with incorrect password
	incorrectHash := hashPassword("wrongpassword")
	_, err = decryptFile(testPath, incorrectHash)
	// Should not cause an error, but data will be wrong
	if err != nil {
		t.Logf("Expected incorrect decryption to complete but with wrong data")
	}
}

func TestEncryptAndSaveFileErrors(t *testing.T) {
	// Test with invalid path
	invalidPath := filepath.Join("/nonexistent/directory", "test.enc")
	passwordHash := hashPassword("testpassword")
	testData := []byte("This is test data")

	// Test encryptAndSaveFile with invalid path
	err := encryptAndSaveFile(testData, invalidPath, passwordHash)
	if err == nil {
		t.Error("Expected error when saving to invalid path, but got none")
		// Clean up if the test unexpectedly passes
		os.Remove(invalidPath)
	}

	// Test decryptFile with non-existent file
	nonExistentPath := filepath.Join(galleryDir, "non_existent_file.enc")
	_, err = decryptFile(nonExistentPath, passwordHash)
	if err == nil {
		t.Error("Expected error when decrypting non-existent file, but got none")
	}

	// Test decryptFile with a file that's too small (no IV)
	tooSmallPath := filepath.Join(galleryDir, "too_small.enc")
	err = os.WriteFile(tooSmallPath, []byte("tooshort"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(tooSmallPath)

	_, err = decryptFile(tooSmallPath, passwordHash)
	if err == nil {
		t.Error("Expected error when decrypting file that's too small for IV, but got none")
	}
}
