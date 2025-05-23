package main

import (
	"strings"
	"testing"
)

func TestBuildBreadcrumbs(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create some encrypted directory names for testing
	encDir1, err := encryptFileName("photos", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}

	encDir2, err := encryptFileName("vacation", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}

	tests := []struct {
		name         string
		currentPath  string
		expectBreadcrumbs []Breadcrumb
	}{
		{
			name:        "Root path",
			currentPath: "",
			expectBreadcrumbs: []Breadcrumb{
				{Name: "Home", Path: "/"},
			},
		},
		{
			name:        "Root path with slash",
			currentPath: "/",
			expectBreadcrumbs: []Breadcrumb{
				{Name: "Home", Path: "/"},
			},
		},
		{
			name:        "Single encrypted directory",
			currentPath: encDir1 + encryptedExt,
			expectBreadcrumbs: []Breadcrumb{
				{Name: "Home", Path: "/"},
				{Name: "photos", Path: "/" + encDir1 + encryptedExt},
			},
		},
		{
			name:        "Nested encrypted directories",
			currentPath: encDir1 + encryptedExt + "/" + encDir2 + encryptedExt,
			expectBreadcrumbs: []Breadcrumb{
				{Name: "Home", Path: "/"},
				{Name: "photos", Path: "/" + encDir1 + encryptedExt},
				{Name: "vacation", Path: "/" + encDir1 + encryptedExt + "/" + encDir2 + encryptedExt},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			breadcrumbs := buildBreadcrumbs(tt.currentPath, passwordHash)

			if len(breadcrumbs) != len(tt.expectBreadcrumbs) {
				t.Errorf("buildBreadcrumbs() returned %d breadcrumbs, want %d",
					len(breadcrumbs), len(tt.expectBreadcrumbs))
				return
			}

			for i, breadcrumb := range breadcrumbs {
				expected := tt.expectBreadcrumbs[i]
				if breadcrumb.Name != expected.Name {
					t.Errorf("buildBreadcrumbs() breadcrumb %d name = %s, want %s",
						i, breadcrumb.Name, expected.Name)
				}
				if breadcrumb.Path != expected.Path {
					t.Errorf("buildBreadcrumbs() breadcrumb %d path = %s, want %s",
						i, breadcrumb.Path, expected.Path)
				}
			}
		})
	}
}

func TestBuildBreadcrumbsWithDecryptionError(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	wrongPasswordHash := hashPassword("wrongpassword")

	// Create an encrypted directory name with one password
	encDir, err := encryptFileName("secret_folder", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}

	// Try to build breadcrumbs with wrong password
	currentPath := encDir + encryptedExt
	breadcrumbs := buildBreadcrumbs(currentPath, wrongPasswordHash)

	// Should have Home + truncated encrypted name
	if len(breadcrumbs) != 2 {
		t.Errorf("buildBreadcrumbs() with wrong password returned %d breadcrumbs, want 2",
			len(breadcrumbs))
		return
	}

	// First should be Home
	if breadcrumbs[0].Name != "Home" {
		t.Errorf("buildBreadcrumbs() first breadcrumb name = %s, want Home", breadcrumbs[0].Name)
	}

	// Second should be truncated encrypted name
	secondName := breadcrumbs[1].Name
	if len(secondName) > 20 {
		t.Errorf("buildBreadcrumbs() truncated name too long: %d chars", len(secondName))
	}

	// Should contain "..." if truncated
	if len(encDir) > 17 && secondName[len(secondName)-3:] != "..." {
		t.Errorf("buildBreadcrumbs() truncated name should end with '...': %s", secondName)
	}
}

func TestGenerateVideoThumbnail(t *testing.T) {
	// This test checks the function behavior when ffmpeg is not available
	tempVideoPath := "/tmp/test_video.mp4"
	tempThumbnailPath := "/tmp/test_thumbnail.jpg"

	err := generateVideoThumbnail(tempVideoPath, tempThumbnailPath)

	// Should return error because ffmpeg is not available in test environment
	if err == nil {
		t.Error("generateVideoThumbnail() expected error when ffmpeg not available")
	}

	// Error should mention ffmpeg or indicate it failed
	if err != nil {
		errorMessage := err.Error()
		if errorMessage != "ffmpeg not found in PATH, cannot generate video thumbnails" &&
		   !strings.Contains(errorMessage, "ffmpeg failed") {
			t.Errorf("generateVideoThumbnail() error = %v, want ffmpeg related error", err)
		}
	}
}

func TestGeneratePlaceholderImageExtended(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expectBytes bool
	}{
		{
			name:        "Video file",
			filename:    "test.mp4",
			expectBytes: true,
		},
		{
			name:        "Image file",
			filename:    "test.jpg",
			expectBytes: true,
		},
		{
			name:        "Unknown file",
			filename:    "test.unknown",
			expectBytes: true,
		},
		{
			name:        "Empty filename",
			filename:    "",
			expectBytes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			placeholderData := generatePlaceholderImage(tt.filename)

			if tt.expectBytes && len(placeholderData) == 0 {
				t.Errorf("generatePlaceholderImage() returned empty data for %s", tt.filename)
			}

			if len(placeholderData) > 0 {
				// Check if it looks like JPEG data (starts with JPEG magic bytes)
				if len(placeholderData) >= 2 && placeholderData[0] != 0xFF || placeholderData[1] != 0xD8 {
					t.Errorf("generatePlaceholderImage() doesn't appear to be JPEG data")
				}
			}
		})
	}
}

func TestEncryptDecryptFileNameEdgeCases(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	wrongPasswordHash := hashPassword("wrongpassword")

	tests := []struct {
		name         string
		filename     string
		passwordHash string
		expectError  bool
	}{
		{
			name:         "Very long filename",
			filename:     "this_is_a_very_long_filename_with_many_characters_to_test_encryption_and_decryption_functionality.txt",
			passwordHash: passwordHash,
			expectError:  false,
		},
		{
			name:         "Filename with special characters",
			filename:     "file@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`.txt",
			passwordHash: passwordHash,
			expectError:  false,
		},
		{
			name:         "Unicode filename",
			filename:     "文件名中文.txt",
			passwordHash: passwordHash,
			expectError:  false,
		},
		{
			name:         "Wrong password",
			filename:     "test.txt",
			passwordHash: wrongPasswordHash,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// First encrypt with correct password
			encrypted, err := encryptFileName(tt.filename, passwordHash)
			if err != nil {
				t.Fatalf("Failed to encrypt filename: %v", err)
			}

			// Then try to decrypt with the test password
			decrypted, err := decryptFileName(encrypted, tt.passwordHash)

			if tt.expectError {
				if err == nil {
					t.Errorf("decryptFileName() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("decryptFileName() error = %v", err)
				return
			}

			if decrypted != tt.filename {
				t.Errorf("decryptFileName() = %s, want %s", decrypted, tt.filename)
			}
		})
	}
}

func TestDecryptFileNameCorruptedData(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name        string
		encryptedHex string
		expectError bool
	}{
		{
			name:        "Invalid hex string",
			encryptedHex: "invalid-hex-string",
			expectError: true,
		},
		{
			name:        "Too short data",
			encryptedHex: "1234",
			expectError: true,
		},
		{
			name:        "Empty string",
			encryptedHex: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decryptFileName(tt.encryptedHex, passwordHash)

			if tt.expectError {
				if err == nil {
					t.Errorf("decryptFileName() expected error for corrupted data, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("decryptFileName() unexpected error = %v", err)
				}
			}
		})
	}
}