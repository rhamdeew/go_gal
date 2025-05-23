package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRangeHeader(t *testing.T) {
	tests := []struct {
		name         string
		rangeHeader  string
		size         int64
		expectRanges []httpRange
		expectError  bool
	}{
		{
			name:         "Single range",
			rangeHeader:  "bytes=0-499",
			size:         1000,
			expectRanges: []httpRange{{start: 0, end: 499}},
			expectError:  false,
		},
		{
			name:         "Range with no end",
			rangeHeader:  "bytes=500-",
			size:         1000,
			expectRanges: []httpRange{{start: 500, end: 999}},
			expectError:  false,
		},
		{
			name:         "Suffix range",
			rangeHeader:  "bytes=-500",
			size:         1000,
			expectRanges: []httpRange{{start: 500, end: 999}},
			expectError:  false,
		},
		{
			name:         "Multiple ranges",
			rangeHeader:  "bytes=0-199, 500-999",
			size:         1000,
			expectRanges: []httpRange{{start: 0, end: 199}, {start: 500, end: 999}},
			expectError:  false,
		},
		{
			name:         "Invalid format",
			rangeHeader:  "invalid-format",
			size:         1000,
			expectRanges: nil,
			expectError:  true,
		},
		{
			name:         "Invalid range spec",
			rangeHeader:  "bytes=abc-def",
			size:         1000,
			expectRanges: []httpRange{},
			expectError:  false,
		},
		{
			name:         "Range beyond file size",
			rangeHeader:  "bytes=1500-2000",
			size:         1000,
			expectRanges: []httpRange{},
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := parseRangeHeader(tt.rangeHeader, tt.size)

			if tt.expectError {
				if err == nil {
					t.Errorf("parseRangeHeader() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseRangeHeader() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if len(ranges) != len(tt.expectRanges) {
				t.Errorf("parseRangeHeader() got %d ranges, want %d", len(ranges), len(tt.expectRanges))
				return
			}

			for i, r := range ranges {
				if r.start != tt.expectRanges[i].start || r.end != tt.expectRanges[i].end {
					t.Errorf("parseRangeHeader() range %d = {%d, %d}, want {%d, %d}",
						i, r.start, r.end, tt.expectRanges[i].start, tt.expectRanges[i].end)
				}
			}
		})
	}
}

func TestGetDecryptedFileSize(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	testData := []byte("This is test content for file size calculation")

	// Create an encrypted test file
	testPath := filepath.Join(galleryDir, "test_size_file.txt.enc")

	err := encryptAndSaveFile(testData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testPath)

	// Test getting decrypted file size
	size, err := getDecryptedFileSize(testPath, passwordHash)
	if err != nil {
		t.Errorf("getDecryptedFileSize() error = %v", err)
		return
	}

	expectedSize := int64(len(testData))
	if size != expectedSize {
		t.Errorf("getDecryptedFileSize() = %d, want %d", size, expectedSize)
	}

	// Test with non-existent file
	_, err = getDecryptedFileSize("nonexistent.txt", passwordHash)
	if err == nil {
		t.Error("getDecryptedFileSize() expected error for non-existent file")
	}

	// Test with file too small
	smallFile := filepath.Join(galleryDir, "small_file.txt.enc")
	err = os.WriteFile(smallFile, []byte("too small"), 0644)
	if err != nil {
		t.Fatalf("Failed to create small test file: %v", err)
	}
	defer os.Remove(smallFile)

	_, err = getDecryptedFileSize(smallFile, passwordHash)
	if err == nil {
		t.Error("getDecryptedFileSize() expected error for file too small")
	}
}

func TestStreamDecryptedFile(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	testData := []byte("This is test content for streaming. It should be long enough to test range requests properly.")

	// Create an encrypted test file
	testPath := filepath.Join(galleryDir, "test_stream_file.txt.enc")

	err := encryptAndSaveFile(testData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testPath)

	tests := []struct {
		name      string
		start     int64
		end       int64
		expectLen int
		expectErr bool
	}{
		{
			name:      "Full file",
			start:     0,
			end:       int64(len(testData)) - 1,
			expectLen: len(testData),
			expectErr: false,
		},
		{
			name:      "First 10 bytes",
			start:     0,
			end:       9,
			expectLen: 10,
			expectErr: false,
		},
		{
			name:      "Middle range",
			start:     10,
			end:       19,
			expectLen: 10,
			expectErr: false,
		},
		{
			name:      "Last 10 bytes",
			start:     int64(len(testData)) - 10,
			end:       int64(len(testData)) - 1,
			expectLen: 10,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := streamDecryptedFile(&buf, testPath, passwordHash, tt.start, tt.end)

			if tt.expectErr {
				if err == nil {
					t.Errorf("streamDecryptedFile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("streamDecryptedFile() error = %v", err)
				return
			}

			if buf.Len() != tt.expectLen {
				t.Errorf("streamDecryptedFile() wrote %d bytes, want %d", buf.Len(), tt.expectLen)
				return
			}

			// Verify the content matches the expected range
			expectedContent := testData[tt.start : tt.end+1]
			if !bytes.Equal(buf.Bytes(), expectedContent) {
				t.Errorf("streamDecryptedFile() content mismatch")
			}
		})
	}
}

func TestServeVideoFile(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test video content (just some bytes that represent a video)
	testVideoData := make([]byte, 1000)
	for i := range testVideoData {
		testVideoData[i] = byte(i % 256)
	}

	// Create an encrypted test video file
	encFileName, err := encryptFileName("test_video.mp4", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	testPath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testVideoData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test video file: %v", err)
	}
	defer os.Remove(testPath)

	tests := []struct {
		name         string
		rangeHeader  string
		expectStatus int
		expectRange  bool
	}{
		{
			name:         "No range request",
			rangeHeader:  "",
			expectStatus: http.StatusOK,
			expectRange:  false,
		},
		{
			name:         "Valid range request",
			rangeHeader:  "bytes=0-499",
			expectStatus: http.StatusPartialContent,
			expectRange:  true,
		},
		{
			name:         "Invalid range request",
			rangeHeader:  "invalid-range",
			expectStatus: http.StatusRequestedRangeNotSatisfiable,
			expectRange:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/view/"+encFileName, nil)
			if err != nil {
				t.Fatal(err)
			}

			if tt.rangeHeader != "" {
				req.Header.Set("Range", tt.rangeHeader)
			}

			rr := httptest.NewRecorder()

			err = serveVideoFile(rr, req, testPath, passwordHash, "video/mp4", "test_video.mp4")

			// For invalid range headers, expect an error to be returned
			if tt.name == "Invalid range request" {
				if err == nil {
					t.Errorf("serveVideoFile() expected error for invalid range, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("serveVideoFile() error = %v", err)
				return
			}

			if rr.Code != tt.expectStatus {
				t.Errorf("serveVideoFile() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Check Accept-Ranges header
			acceptRanges := rr.Header().Get("Accept-Ranges")
			if acceptRanges != "bytes" {
				t.Errorf("serveVideoFile() Accept-Ranges = %s, want bytes", acceptRanges)
			}

			// Check Content-Range header for range requests
			if tt.expectRange {
				contentRange := rr.Header().Get("Content-Range")
				if contentRange == "" {
					t.Error("serveVideoFile() missing Content-Range header for range request")
				}
			}
		})
	}
}

func TestServeVideoFileWithWrongPassword(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	wrongPasswordHash := hashPassword("wrongpassword")

	// Create test video content
	testVideoData := []byte("test video content")

	// Create an encrypted test video file with correct password
	encFileName, err := encryptFileName("test_video.mp4", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	testPath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testVideoData, testPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test video file: %v", err)
	}
	defer os.Remove(testPath)

	req, err := http.NewRequest("GET", "/view/"+encFileName, nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()

	// Try to serve with wrong password
	err = serveVideoFile(rr, req, testPath, wrongPasswordHash, "video/mp4", "test_video.mp4")
	if err == nil {
		t.Error("serveVideoFile() expected error with wrong password")
		return
	}

	if !strings.Contains(err.Error(), "incorrect password") {
		t.Errorf("serveVideoFile() error = %v, want error containing 'incorrect password'", err)
	}
}
