package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	t.Parallel()
	// Create temporary files for testing
	certPath := filepath.Join(galleryDir, "test_cert.pem")
	keyPath := filepath.Join(galleryDir, "test_key.pem")

	// Clean up afterwards
	defer os.Remove(certPath)
	defer os.Remove(keyPath)

	// Generate the certificate
	err := generateSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	// Verify that the files were created
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file was not created at %s", certPath)
	}

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Errorf("Key file was not created at %s", keyPath)
	}

	// Verify the certificate contains the expected PEM header
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}

	if !bytes.Contains(certData, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Error("Certificate file does not contain the expected PEM header")
	}

	// Verify the key contains the expected PEM header
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	if !bytes.Contains(keyData, []byte("-----BEGIN RSA PRIVATE KEY-----")) {
		t.Error("Key file does not contain the expected PEM header")
	}
}

func TestAESEncryptionDecryption(t *testing.T) {
	t.Parallel()
	// Generate a password hash
	passwordHash := hashPassword("test_password")

	// Create an AES cipher
	block, err := createAESCipher(passwordHash)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Test data to encrypt/decrypt
	originalData := []byte("This is test data for AES encryption and decryption")

	// Encrypt the data
	encrypted := make([]byte, aes.BlockSize+len(originalData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], originalData)

	// Decrypt the data
	decrypted := make([]byte, len(encrypted)-aes.BlockSize)
	decStream := cipher.NewCFBDecrypter(block, encrypted[:aes.BlockSize])
	decStream.XORKeyStream(decrypted, encrypted[aes.BlockSize:])

	// Compare original and decrypted data
	if !bytes.Equal(originalData, decrypted) {
		t.Errorf("Decrypted data does not match original data.\nOriginal: %s\nDecrypted: %s",
			string(originalData), string(decrypted))
	}
}

func TestHashPasswordAlgorithm(t *testing.T) {
	t.Parallel()
	// Test the internal implementation of hashPassword to ensure it uses SHA-256
	password := "test_password"

	// Compute hash directly
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(saltBytes)
	directHash := hex.EncodeToString(h.Sum(nil))

	// Compare with the function's result
	funcHash := hashPassword(password)

	if directHash != funcHash {
		t.Errorf("Hash algorithm mismatch.\nDirect: %s\nFunction: %s", directHash, funcHash)
	}
}

func TestEncryptionIdempotence(t *testing.T) {
	t.Parallel()
	// Test to ensure that consecutive encryptions with the same password produce different ciphertexts
	// (due to random IV), but decryption still works correctly

	password := "test_password"
	passwordHash := hashPassword(password)
	data := []byte("Test data for encryption idempotence test")

	// First encryption
	encrypted1, err := encryptData(data, passwordHash)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	// Second encryption
	encrypted2, err := encryptData(data, passwordHash)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different (due to random IV)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("Two consecutive encryptions produced identical ciphertexts")
	}

	// But both should decrypt to the original data
	decrypted1, err := decryptData(encrypted1, passwordHash)
	if err != nil {
		t.Fatalf("Decryption of first ciphertext failed: %v", err)
	}

	decrypted2, err := decryptData(encrypted2, passwordHash)
	if err != nil {
		t.Fatalf("Decryption of second ciphertext failed: %v", err)
	}

	if !bytes.Equal(data, decrypted1) {
		t.Error("First decryption does not match original data")
	}

	if !bytes.Equal(data, decrypted2) {
		t.Error("Second decryption does not match original data")
	}
}

// Helper function for encryption (directly copied from main app logic to ensure tests match implementation)
func encryptData(data []byte, passwordHash string) ([]byte, error) {
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, aes.BlockSize+len(data))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], data)

	return encrypted, nil
}

// Helper function for decryption (directly copied from main app logic to ensure tests match implementation)
func decryptData(data []byte, passwordHash string) ([]byte, error) {
	block, err := createAESCipher(passwordHash)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	decrypted := make([]byte, len(data)-aes.BlockSize)

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(decrypted, data[aes.BlockSize:])

	return decrypted, nil
}

// Benchmark tests for performance-critical crypto operations

func BenchmarkHashPassword(b *testing.B) {
	password := "testpassword123"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hashPassword(password)
	}
}

func BenchmarkCreateAESCipher(b *testing.B) {
	passwordHash := hashPassword("testpassword123")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := createAESCipher(passwordHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptDecryptData(b *testing.B) {
	testData := []byte("This is a test string for encryption benchmarking. It should be reasonably long to get meaningful performance numbers.")
	passwordHash := hashPassword("testpassword123")

	b.Run("Encrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptData(testData, passwordHash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Pre-encrypt data for decrypt benchmark
	encryptedData, err := encryptData(testData, passwordHash)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("Decrypt", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := decryptData(encryptedData, passwordHash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkEncryptDecryptFileName(b *testing.B) {
	filename := "test_file_with_long_name_for_benchmarking.jpg"
	passwordHash := hashPassword("testpassword123")

	b.Run("EncryptFileName", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := encryptFileName(filename, passwordHash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	// Pre-encrypt filename for decrypt benchmark
	encryptedName, err := encryptFileName(filename, passwordHash)
	if err != nil {
		b.Fatal(err)
	}

	b.Run("DecryptFileName", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := decryptFileName(encryptedName, passwordHash)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
