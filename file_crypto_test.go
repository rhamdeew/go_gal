package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptAndSaveFileFunctions(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

func TestEncryptAndSaveFileStream(t *testing.T) {
	t.Parallel()
	// Create a temporary test file path
	testPath := filepath.Join(galleryDir, "test_stream_file.txt"+encryptedExt)

	// Generate a test password hash
	passwordHash := hashPassword("testpassword")

	// Test data - simulate a large file with repeated chunks
	chunk := []byte("This is a test chunk for streaming encryption. ")
	largeData := bytes.Repeat(chunk, 100) // ~4KB of data

	// Test encryptAndSaveFileStream with a reader
	reader := bytes.NewReader(largeData)
	err := encryptAndSaveFileStream(reader, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt and save file stream: %v", err)
	}
	defer os.Remove(testPath)

	// Verify the file exists
	if _, err := os.Stat(testPath); os.IsNotExist(err) {
		t.Fatalf("Encrypted file does not exist at %s", testPath)
	}

	// Test decryptFile to verify the streaming encryption worked
	decrypted, err := decryptFile(testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt stream-encrypted file: %v", err)
	}

	// Verify the decrypted content matches original
	if !bytes.Equal(largeData, decrypted) {
		t.Errorf("Decrypted stream data does not match original.\nExpected length: %d\nGot length: %d",
			len(largeData), len(decrypted))
	}
}

func TestEncryptAndSaveFileStreamLargeFile(t *testing.T) {
	t.Parallel()
	// Create a temporary test file path
	testPath := filepath.Join(galleryDir, "test_large_stream_file.bin"+encryptedExt)

	// Generate a test password hash
	passwordHash := hashPassword("testpassword")

	// Test data - simulate a larger file (1MB)
	chunk := make([]byte, 32*1024) // 32KB chunks (matching the buffer size in encryptAndSaveFileStream)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}
	largeData := bytes.Repeat(chunk, 32) // 1MB of data

	// Test encryptAndSaveFileStream with a reader
	reader := bytes.NewReader(largeData)
	err := encryptAndSaveFileStream(reader, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt and save large file stream: %v", err)
	}
	defer os.Remove(testPath)

	// Verify the file exists
	fileInfo, err := os.Stat(testPath)
	if err != nil {
		t.Fatalf("Failed to stat encrypted file: %v", err)
	}

	// Encrypted file should be larger than original (IV + HMAC + overhead)
	if fileInfo.Size() <= int64(len(largeData)) {
		t.Errorf("Encrypted file size (%d) should be larger than original data size (%d)",
			fileInfo.Size(), len(largeData))
	}

	// Test decryptFile to verify the streaming encryption worked
	decrypted, err := decryptFile(testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt large stream-encrypted file: %v", err)
	}

	// Verify the decrypted content matches original
	if !bytes.Equal(largeData, decrypted) {
		t.Errorf("Decrypted large stream data does not match original.\nExpected length: %d\nGot length: %d",
			len(largeData), len(decrypted))
	}
}

func TestEncryptAndSaveFileStreamErrors(t *testing.T) {
	t.Parallel()
	// Test with invalid path
	invalidPath := filepath.Join("/nonexistent/directory", "test.enc")
	passwordHash := hashPassword("testpassword")
	testData := []byte("This is test data")

	// Test encryptAndSaveFileStream with invalid path
	reader := bytes.NewReader(testData)
	err := encryptAndSaveFileStream(reader, invalidPath, passwordHash)
	if err == nil {
		t.Error("Expected error when saving stream to invalid path, but got none")
		// Clean up if the test unexpectedly passes
		os.Remove(invalidPath)
	}

	// Test encryptAndSaveFileStream with nil reader
	testPath2 := filepath.Join(galleryDir, "test_nil_reader.enc")
	err = encryptAndSaveFileStream(nil, testPath2, passwordHash)
	if err == nil {
		t.Error("Expected error with nil reader, but got none")
		os.Remove(testPath2)
	}
}

func TestCipherWriteWriter(t *testing.T) {
	t.Parallel()
	passwordHash := hashPassword("testpassword")

	// Create a cipher
	block, err := createAESCipher(passwordHash)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Create IV
	iv := make([]byte, aes.BlockSize)
	for i := range iv {
		iv[i] = byte(i)
	}

	// Create cipher stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Create a buffer to hold encrypted output
	var buf bytes.Buffer

	// Create cipherWriteWriter
	cw := &cipherWriteWriter{
		stream: stream,
		writer: &buf,
	}

	// Test writing data in chunks
	testData := []byte("This is test data for cipherWriteWriter")
	chunks := [][]byte{
		testData[0:10],
		testData[10:20],
		testData[20:],
	}

	totalWritten := 0
	for _, chunk := range chunks {
		n, err := cw.Write(chunk)
		if err != nil {
			t.Fatalf("Failed to write chunk: %v", err)
		}
		if n != len(chunk) {
			t.Errorf("Expected to write %d bytes, wrote %d", len(chunk), n)
		}
		totalWritten += n
	}

	// Verify we wrote the correct amount
	if totalWritten != len(testData) {
		t.Errorf("Expected to write %d bytes total, wrote %d", len(testData), totalWritten)
	}

	// Verify the buffer has encrypted data (different from original)
	encryptedData := buf.Bytes()
	if bytes.Equal(encryptedData, testData) {
		t.Error("Encrypted data should differ from original data")
	}

	// Verify the encrypted data is the same length as original
	if len(encryptedData) != len(testData) {
		t.Errorf("Encrypted data length (%d) should equal original length (%d)",
			len(encryptedData), len(testData))
	}
}

func TestCipherWriteWriterEmptyWrite(t *testing.T) {
	t.Parallel()
	passwordHash := hashPassword("testpassword")

	// Create a cipher
	block, err := createAESCipher(passwordHash)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Create IV
	iv := make([]byte, aes.BlockSize)

	// Create cipher stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// Create a buffer
	var buf bytes.Buffer

	// Create cipherWriteWriter
	cw := &cipherWriteWriter{
		stream: stream,
		writer: &buf,
	}

	// Test writing empty data
	n, err := cw.Write([]byte{})
	if err != nil {
		t.Fatalf("Failed to write empty data: %v", err)
	}
	if n != 0 {
		t.Errorf("Expected to write 0 bytes for empty input, wrote %d", n)
	}

	// Verify buffer is still empty
	if buf.Len() != 0 {
		t.Errorf("Buffer should be empty after writing empty data, but has %d bytes", buf.Len())
	}
}

func TestEncryptAndSaveFileStreamVsRegular(t *testing.T) {
	t.Parallel()
	// Test that streaming encryption produces the same result as regular encryption

	// Create two test file paths
	testPath1 := filepath.Join(galleryDir, "test_regular.enc")
	testPath2 := filepath.Join(galleryDir, "test_stream.enc")

	passwordHash := hashPassword("testpassword")
	testData := []byte("This is test data for comparing encryption methods")

	defer os.Remove(testPath1)
	defer os.Remove(testPath2)

	// Encrypt using regular method
	err := encryptAndSaveFile(testData, testPath1, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt with regular method: %v", err)
	}

	// Encrypt using streaming method
	reader := bytes.NewReader(testData)
	err = encryptAndSaveFileStream(reader, testPath2, passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt with streaming method: %v", err)
	}

	// Both files should decrypt to the same data
	decrypted1, err := decryptFile(testPath1, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt regular file: %v", err)
	}

	decrypted2, err := decryptFile(testPath2, passwordHash)
	if err != nil {
		t.Fatalf("Failed to decrypt stream file: %v", err)
	}

	// Both should match original data
	if !bytes.Equal(decrypted1, testData) {
		t.Error("Regular decryption does not match original")
	}
	if !bytes.Equal(decrypted2, testData) {
		t.Error("Stream decryption does not match original")
	}
	if !bytes.Equal(decrypted1, decrypted2) {
		t.Error("Regular and stream decryption do not match")
	}
}
