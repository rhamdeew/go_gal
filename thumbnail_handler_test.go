package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThumbnailHandler(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Ensure thumbnails directory exists
	err := os.MkdirAll(thumbnailsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create thumbnails directory: %v", err)
	}

	// Create test image data
	testImageData := createTestJPEG()

	// Create an encrypted test image file
	encFileName, err := encryptFileName("test_image.jpg", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	originalFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testImageData, originalFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test image file: %v", err)
	}
	defer os.Remove(originalFilePath)

	tests := []struct {
		name           string
		path           string
		setupThumbnail bool
		expectStatus   int
		expectError    bool
	}{
		{
			name:           "Existing thumbnail",
			path:           encFileName,
			setupThumbnail: true,
			expectStatus:   http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Generate thumbnail from original",
			path:           encFileName,
			setupThumbnail: false,
			expectStatus:   http.StatusOK,
			expectError:    false,
		},
		{
			name:           "Non-existent file",
			path:           "nonexistent",
			setupThumbnail: false,
			expectStatus:   http.StatusOK, // Should return placeholder
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup thumbnail if needed
			thumbnailPath := filepath.Join(thumbnailsDir, tt.path+encryptedExt)
			if tt.setupThumbnail {
				// Create a thumbnail (just reuse the image data for simplicity)
				err = encryptAndSaveFile(testImageData, thumbnailPath, passwordHash)
				if err != nil {
					t.Fatalf("Failed to create test thumbnail: %v", err)
				}
				defer os.Remove(thumbnailPath)
			}

			// Create request
			req, err := http.NewRequest("GET", "/thumbnail/"+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			// Create session
			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			session.Values["password_hash"] = passwordHash
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			// Set up URL vars
			req = SetURLVars(req, map[string]string{"path": tt.path})

			// Reset recorder and serve request
			rr = httptest.NewRecorder()
			thumbnailHandler(rr, req)

			// Check response
			if rr.Code != tt.expectStatus {
				t.Errorf("thumbnailHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Check content type for successful responses
			if rr.Code == http.StatusOK {
				contentType := rr.Header().Get("Content-Type")
				if contentType != "image/jpeg" {
					t.Errorf("thumbnailHandler() Content-Type = %s, want image/jpeg", contentType)
				}
			}
		})
	}
}

func TestThumbnailHandlerUnauthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", "/thumbnail/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set up URL vars
	req = SetURLVars(req, map[string]string{"path": "test"})

	rr := httptest.NewRecorder()
	thumbnailHandler(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("thumbnailHandler() unauthenticated status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("thumbnailHandler() unauthenticated redirect = %s, want /", location)
	}
}

func TestThumbnailHandlerWithWrongPassword(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	wrongPasswordHash := hashPassword("wrongpassword")

	// Create test image data
	testImageData := createTestJPEG()

	// Create an encrypted test image file with correct password
	encFileName, err := encryptFileName("test_image.jpg", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	originalFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testImageData, originalFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test image file: %v", err)
	}
	defer os.Remove(originalFilePath)

	// Create encrypted thumbnail with correct password
	thumbnailPath := filepath.Join(thumbnailsDir, encFileName+encryptedExt)
	err = os.MkdirAll(filepath.Dir(thumbnailPath), 0755)
	if err != nil {
		t.Fatalf("Failed to create thumbnail directory: %v", err)
	}

	err = encryptAndSaveFile(testImageData, thumbnailPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test thumbnail: %v", err)
	}
	defer os.Remove(thumbnailPath)

	// Create request
	req, err := http.NewRequest("GET", "/thumbnail/"+encFileName, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create session with wrong password
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = wrongPasswordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	// Set up URL vars
	req = SetURLVars(req, map[string]string{"path": encFileName})

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	thumbnailHandler(rr, req)

	// Should redirect to login with error
	if rr.Code != http.StatusSeeOther {
		t.Errorf("thumbnailHandler() wrong password status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=incorrect_password") {
		t.Errorf("thumbnailHandler() wrong password redirect = %s, want error=incorrect_password", location)
	}
}

func TestThumbnailHandlerVideoFile(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create fake video data
	testVideoData := []byte("fake video data for testing")

	// Create an encrypted test video file
	encFileName, err := encryptFileName("test_video.mp4", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	originalFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testVideoData, originalFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test video file: %v", err)
	}
	defer os.Remove(originalFilePath)

	// Create request
	req, err := http.NewRequest("GET", "/thumbnail/"+encFileName, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = passwordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	// Set up URL vars
	req = SetURLVars(req, map[string]string{"path": encFileName})

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	thumbnailHandler(rr, req)

	// Should return placeholder for video (since we don't have ffmpeg in test)
	if rr.Code != http.StatusOK {
		t.Errorf("thumbnailHandler() video status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "image/jpeg" {
		t.Errorf("thumbnailHandler() video Content-Type = %s, want image/jpeg", contentType)
	}
}

func TestThumbnailHandlerInvalidPath(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name string
		path string
	}{
		{
			name: "Empty path",
			path: "",
		},
		{
			name: "Path traversal attempt",
			path: "../../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/thumbnail/"+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			// Create session
			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			session.Values["password_hash"] = passwordHash
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			// Set up URL vars
			req = SetURLVars(req, map[string]string{"path": tt.path})

			// Reset recorder and serve request
			rr = httptest.NewRecorder()
			thumbnailHandler(rr, req)

			// Should handle gracefully (either bad request or placeholder)
			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusOK {
				t.Errorf("thumbnailHandler() invalid path status = %d, want %d or %d",
					rr.Code, http.StatusBadRequest, http.StatusOK)
			}
		})
	}
}
