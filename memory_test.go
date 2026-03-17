package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"testing"
)

// TestEncryptStreamMemoryUsage measures actual heap allocation during streaming
// encryption of a large file, confirming O(1) memory behaviour.
//
// Run with: go test -v -run TestEncryptStreamMemoryUsage
func TestEncryptStreamMemoryUsage(t *testing.T) {
	const fileSizeMB = 100
	const fileSizeBytes = fileSizeMB * 1024 * 1024

	passwordHash := hashPassword("testpassword123")

	tmpFile, err := os.CreateTemp(t.TempDir(), "enc_out_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	outPath := tmpFile.Name()
	defer os.Remove(outPath)

	// Fill 100 MB of input data (done before measurement to exclude its allocation)
	input := bytes.Repeat([]byte("A"), fileSizeBytes)

	// Force GC to get a clean baseline
	runtime.GC()
	runtime.GC()

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	err = encryptAndSaveFileStreamV2(bytes.NewReader(input), outPath, passwordHash)
	if err != nil {
		t.Fatalf("encryptAndSaveFileStreamV2 failed: %v", err)
	}

	runtime.ReadMemStats(&after)

	// TotalAlloc counts every allocation made since process start — the delta
	// shows exactly how much was allocated during our call.
	allocDelta := int64(after.TotalAlloc) - int64(before.TotalAlloc)
	heapGrowth := int64(after.HeapInuse) - int64(before.HeapInuse)

	fmt.Printf("\n=== Memory usage for %d MB encryption ===\n", fileSizeMB)
	fmt.Printf("Heap allocations (TotalAlloc delta): %d bytes (%.2f MB)\n",
		allocDelta, float64(allocDelta)/1024/1024)
	fmt.Printf("Live heap growth (HeapInuse delta):  %d bytes (%.2f MB)\n",
		heapGrowth, float64(heapGrowth)/1024/1024)
	fmt.Printf("NumGC during call: %d\n", after.NumGC-before.NumGC)

	// The streaming implementation should allocate far less than the file size.
	// We allow up to 5 MB for buffers, HMAC state, etc. — nowhere near 100 MB.
	const maxAllowedMB = 5
	const maxAllowedBytes = maxAllowedMB * 1024 * 1024
	if allocDelta > maxAllowedBytes {
		t.Errorf("Too much memory allocated: %.2f MB (limit %d MB) — "+
			"streaming is likely buffering the whole file",
			float64(allocDelta)/1024/1024, maxAllowedMB)
	} else {
		t.Logf("PASS: only %.2f MB allocated for a %d MB file", float64(allocDelta)/1024/1024, fileSizeMB)
	}
}

// TestBackwardCompatibility verifies that:
//  1. Files written by the new (seek-back) encoder can be decrypted by decryptFileV2.
//  2. Files assembled manually in the V2 binary format (as the old buffered encoder
//     produced them) are also decryptable — confirming the on-disk format is identical.
//
// Run with: go test -v -run TestBackwardCompatibility
func TestBackwardCompatibility(t *testing.T) {
	passwordHash := hashPassword("testpassword123")

	key, err := hex.DecodeString(passwordHash)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) > 32 {
		key = key[:32]
	} else if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		key = padded
	}

	payload := []byte("backward compatibility test payload — привет мир 🎉")

	// --- Part 1: new encoder → decryptFileV2 ---
	t.Run("NewEncoderDecodedByV2Reader", func(t *testing.T) {
		path := t.TempDir() + "/new_enc.bin"
		if err := encryptAndSaveFileStreamV2(bytes.NewReader(payload), path, passwordHash); err != nil {
			t.Fatalf("encryptAndSaveFileStreamV2: %v", err)
		}
		got, err := decryptFileV2(path, passwordHash)
		if err != nil {
			t.Fatalf("decryptFileV2 failed on new-encoder file: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("roundtrip mismatch\ngot:  %q\nwant: %q", got, payload)
		}
	})

	// --- Part 2: hand-crafted V2 file (simulates old buffered encoder output) ---
	// The old encoder did:
	//   1. encrypt all bytes into encryptedBuffer (bytes.Buffer)
	//   2. HMAC(key, IV || encryptedBuffer.Bytes())
	//   3. write: magic | IV | HMAC | encryptedBuffer.Bytes()
	// We replicate that exactly and confirm decryptFileV2 reads it.
	t.Run("OldFormatDecodedByV2Reader", func(t *testing.T) {
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			t.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := make([]byte, len(payload))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext, payload)

		h := hmac.New(sha256.New, key)
		h.Write(iv)
		h.Write(ciphertext)
		mac := h.Sum(nil)

		// Assemble exactly as the old encoder wrote to disk
		var oldFile []byte
		oldFile = append(oldFile, fileFormatV2Magic)
		oldFile = append(oldFile, iv...)
		oldFile = append(oldFile, mac...)
		oldFile = append(oldFile, ciphertext...)

		path := t.TempDir() + "/old_format.bin"
		if err := os.WriteFile(path, oldFile, 0600); err != nil {
			t.Fatal(err)
		}

		got, err := decryptFileV2(path, passwordHash)
		if err != nil {
			t.Fatalf("decryptFileV2 failed on hand-crafted V2 file: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("old-format roundtrip mismatch\ngot:  %q\nwant: %q", got, payload)
		}
	})

	// --- Part 3: new encoder output is bit-for-bit V2 compliant ---
	// Verify the HMAC stored in the file matches HMAC(key, IV||ciphertext).
	t.Run("HMACStoredCorrectly", func(t *testing.T) {
		path := t.TempDir() + "/hmac_check.bin"
		if err := encryptAndSaveFileStreamV2(bytes.NewReader(payload), path, passwordHash); err != nil {
			t.Fatal(err)
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		// Layout: [1 magic][16 IV][32 HMAC][N ciphertext]
		const overhead = 1 + aes.BlockSize + 32
		if len(raw) < overhead {
			t.Fatalf("file too small: %d bytes", len(raw))
		}
		iv := raw[1 : 1+aes.BlockSize]
		storedMAC := raw[1+aes.BlockSize : overhead]
		ciphertext := raw[overhead:]

		h := hmac.New(sha256.New, key)
		h.Write(iv)
		h.Write(ciphertext)
		expectedMAC := h.Sum(nil)

		if !hmac.Equal(storedMAC, expectedMAC) {
			t.Error("HMAC stored by new encoder does not match expected HMAC(key, IV||ciphertext)")
		}
	})
}

// BenchmarkEncryptStream benchmarks encryptAndSaveFileStreamV2 on a 100 MB
// reader and reports bytes allocated per operation.
//
// Run with: go test -bench=BenchmarkEncryptStream -benchmem -benchtime=1x
func BenchmarkEncryptStream(b *testing.B) {
	const fileSizeMB = 100
	const fileSizeBytes = fileSizeMB * 1024 * 1024

	passwordHash := hashPassword("testpassword123")
	input := bytes.Repeat([]byte("V"), fileSizeBytes) // pre-built, not measured

	b.ReportAllocs()
	b.SetBytes(fileSizeBytes)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		outPath := b.TempDir() + "/enc_bench.bin"
		err := encryptAndSaveFileStreamV2(bytes.NewReader(input), outPath, passwordHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}
