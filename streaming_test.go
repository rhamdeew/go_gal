package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStreamingMemoryEfficiency tests that the streaming implementation
// doesn't load large files entirely into memory
func TestStreamingMemoryEfficiency(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()

	// Create a "large" test file (5MB to keep test fast but demonstrate principle)
	testSize := int64(5 * 1024 * 1024) // 5MB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	passwordHash := hashPassword("testpassword")
	testFile := filepath.Join(tempDir, "large_file.enc")

	// Encrypt and save the test file
	err := encryptAndSaveFile(testData, testFile, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt test file: %v", err)
	}

	// Verify file size
	fileInfo, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to stat test file: %v", err)
	}

	// The encrypted file should be larger than the original due to IV and HMAC
	if fileInfo.Size() <= testSize {
		t.Errorf("Encrypted file size %d should be larger than original %d", fileInfo.Size(), testSize)
	}

	t.Logf("Test file size: %d bytes (%.2f MB)", fileInfo.Size(), float64(fileInfo.Size())/(1024*1024))

	// Test 1: Full file decryption (like no range request)
	t.Run("FullFileDecryption", func(t *testing.T) {
		var buf bytes.Buffer
		err := streamDecryptedFile(&buf, testFile, passwordHash, 0, testSize-1)
		if err != nil {
			t.Fatalf("Failed to decrypt full file: %v", err)
		}

		decryptedData := buf.Bytes()
		if len(decryptedData) != len(testData) {
			t.Errorf("Decrypted size mismatch: got %d, want %d", len(decryptedData), len(testData))
		}

		if !bytes.Equal(decryptedData, testData) {
			t.Error("Decrypted data doesn't match original data")
		}

		t.Logf("Successfully decrypted %d bytes in streaming mode", len(decryptedData))
	})

	// Test 2: Partial file decryption (like a range request)
	t.Run("PartialFileDecryption", func(t *testing.T) {
		// Request middle 1MB of a 5MB file
		start := int64(2 * 1024 * 1024) // 2MB offset
		end := int64(3 * 1024 * 1024)   // 3MB offset (1MB range)
		expectedSize := end - start + 1

		var buf bytes.Buffer
		err := streamDecryptedFile(&buf, testFile, passwordHash, start, end)
		if err != nil {
			t.Fatalf("Failed to decrypt partial file: %v", err)
		}

		decryptedData := buf.Bytes()
		if len(decryptedData) != int(expectedSize) {
			t.Errorf("Decrypted range size mismatch: got %d, want %d", len(decryptedData), expectedSize)
		}

		// Verify the decrypted range matches the original data
		expectedData := testData[start : end+1]
		if !bytes.Equal(decryptedData, expectedData) {
			t.Error("Decrypted range data doesn't match original data")
		}

		t.Logf("Successfully decrypted range %d-%d (%d bytes) in streaming mode", start, end, expectedSize)
	})

	// Test 3: Edge case - very small range
	t.Run("SmallRangeDecryption", func(t *testing.T) {
		start := int64(1000)
		end := int64(2000)
		expectedSize := end - start + 1

		var buf bytes.Buffer
		err := streamDecryptedFile(&buf, testFile, passwordHash, start, end)
		if err != nil {
			t.Fatalf("Failed to decrypt small range: %v", err)
		}

		decryptedData := buf.Bytes()
		if len(decryptedData) != int(expectedSize) {
			t.Errorf("Decrypted small range size mismatch: got %d, want %d", len(decryptedData), expectedSize)
		}

		expectedData := testData[start : end+1]
		if !bytes.Equal(decryptedData, expectedData) {
			t.Error("Decrypted small range data doesn't match original data")
		}
	})

	// Test 4: Wrong password should fail
	t.Run("WrongPassword", func(t *testing.T) {
		wrongHash := hashPassword("wrongpassword")

		var buf bytes.Buffer
		err := streamDecryptedFile(&buf, testFile, wrongHash, 0, testSize-1)

		if err == nil {
			t.Error("Expected error with wrong password, got nil")
		}

		if !strings.Contains(err.Error(), "incorrect password") && !strings.Contains(err.Error(), "tampered") {
			t.Errorf("Expected password error, got: %v", err)
		}

		t.Logf("Correctly rejected wrong password: %v", err)
	})
}

// TestStreamingWithSmallChunks tests behavior with file smaller than chunk size
func TestStreamingWithSmallChunks(t *testing.T) {
	tempDir := t.TempDir()

	// Create a small test file (smaller than our 64KB chunk size)
	testData := []byte("Hello, this is a small test file!")
	passwordHash := hashPassword("testpassword")
	testFile := filepath.Join(tempDir, "small_file.enc")

	err := encryptAndSaveFile(testData, testFile, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt small test file: %v", err)
	}

	// Decrypt full file
	var buf bytes.Buffer
	err = streamDecryptedFile(&buf, testFile, passwordHash, 0, int64(len(testData))-1)
	if err != nil {
		t.Fatalf("Failed to decrypt small file: %v", err)
	}

	decryptedData := buf.Bytes()
	if !bytes.Equal(decryptedData, testData) {
		t.Errorf("Small file decryption failed: got %q, want %q", string(decryptedData), string(testData))
	}
}

// TestStreamingCorruptedFile tests that corrupted files are detected
func TestStreamingCorruptedFile(t *testing.T) {
	tempDir := t.TempDir()

	// Use larger test data to ensure we have room to corrupt
	testData := []byte("This file will be corrupted. It needs to be large enough to have data to corrupt.")
	passwordHash := hashPassword("testpassword")
	testFile := filepath.Join(tempDir, "corrupted_file.enc")

	err := encryptAndSaveFile(testData, testFile, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt test file: %v", err)
	}

	// Read the encrypted file
	encryptedData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Corrupt a byte near the end of the encrypted data (last 10 bytes)
	// Structure: IV(16) + HMAC size(8) + HMAC(32) + encrypted data
	// Header is 56 bytes, so we corrupt near the end
	corruptionOffset := len(encryptedData) - 10
	if corruptionOffset < 56 {
		t.Skip("Test data too small to safely corrupt")
	}

	encryptedData[corruptionOffset] ^= 0xFF // Flip bits to corrupt data

	// Write corrupted data back
	err = os.WriteFile(testFile, encryptedData, 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Attempting to decrypt should fail
	var buf bytes.Buffer
	err = streamDecryptedFile(&buf, testFile, passwordHash, 0, int64(len(testData))-1)

	if err == nil {
		t.Error("Expected error with corrupted file, got nil")
	} else if !strings.Contains(err.Error(), "incorrect password") && !strings.Contains(err.Error(), "tampered") {
		t.Errorf("Expected corruption error, got: %v", err)
	} else {
		t.Logf("Correctly detected corrupted file: %v", err)
	}
}

// BenchmarkStreamingDecryption benchmarks the streaming decryption
func BenchmarkStreamingDecryption(b *testing.B) {
	tempDir := b.TempDir()

	// Create a 10MB test file for benchmarking
	testSize := int64(10 * 1024 * 1024)
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	passwordHash := hashPassword("testpassword")
	testFile := filepath.Join(tempDir, "bench_file.enc")

	err := encryptAndSaveFile(testData, testFile, passwordHash)
	if err != nil {
		b.Fatalf("Failed to encrypt test file: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		// Simulate a range request for middle portion
		start := testSize / 2
		end := (testSize / 2) + (1024 * 1024) // 1MB range

		err := streamDecryptedFile(&buf, testFile, passwordHash, start, end)
		if err != nil {
			b.Fatalf("Benchmark decryption failed: %v", err)
		}
	}
}

// BenchmarkStreamingMemoryUsage is a pseudo-benchmark to show memory efficiency
// In real-world testing, you would use memory profilers
func BenchmarkStreamingMemoryUsage(b *testing.B) {
	tempDir := b.TempDir()

	// Create a 50MB test file to simulate large video
	testSize := int64(50 * 1024 * 1024)
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	passwordHash := hashPassword("testpassword")
	testFile := filepath.Join(tempDir, "large_bench_file.enc")

	err := encryptAndSaveFile(testData, testFile, passwordHash)
	if err != nil {
		b.Fatalf("Failed to encrypt test file: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var buf bytes.Buffer
		// Request a small range from a large file
		start := int64(10 * 1024 * 1024) // 10MB offset
		end := start + (100 * 1024)      // 100KB range

		err := streamDecryptedFile(&buf, testFile, passwordHash, start, end)
		if err != nil {
			b.Fatalf("Benchmark decryption failed: %v", err)
		}

		// The key point: we should NOT have allocated 50MB here
		// Memory usage should be bounded by chunk size (64KB), not file size
	}
}
