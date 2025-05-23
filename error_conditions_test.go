package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateDirHandlerEdgeCases(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		currentDir   string
		dirName      string
		expectStatus int
	}{
		{
			name:         "Empty directory name",
			currentDir:   "/",
			dirName:      "",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Non-existent parent directory",
			currentDir:   "/nonexistent",
			dirName:      "newdir",
			expectStatus: http.StatusNotFound,
		},
		{
			name:         "Path traversal in current dir",
			currentDir:   "../../../etc",
			dirName:      "newdir",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Valid directory creation",
			currentDir:   "/",
			dirName:      "validdir",
			expectStatus: http.StatusSeeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create form data
			form := url.Values{}
			form.Add("currentDir", tt.currentDir)
			form.Add("dirName", tt.dirName)

			// Create request
			req, err := http.NewRequest("POST", "/createdir", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

			// Reset recorder and serve request
			rr = httptest.NewRecorder()
			createDirHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("createDirHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Clean up created directory if test was successful
			if tt.expectStatus == http.StatusSeeOther && tt.dirName != "" {
				encDirName, _ := encryptFileName(tt.dirName, passwordHash)
				testDirPath := filepath.Join(galleryDir, encDirName+encryptedExt)
				os.RemoveAll(testDirPath)
			}
		})
	}
}

func TestGalleryHandlerWithWrongPassword(t *testing.T) {
	passwordHash := hashPassword("testpassword")
	wrongPasswordHash := hashPassword("wrongpassword")

	// Create an encrypted directory with correct password
	encDirName, err := encryptFileName("secret_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}

	testDirPath := filepath.Join(galleryDir, encDirName+encryptedExt)
	err = os.MkdirAll(testDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDirPath)

	// Try to access with wrong password
	req, err := http.NewRequest("GET", "/gallery/", nil)
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
	req = SetURLVars(req, map[string]string{"path": ""})

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	galleryHandler(rr, req)

	// Should redirect to login with error
	if rr.Code != http.StatusSeeOther {
		t.Errorf("galleryHandler() wrong password status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=incorrect_password") {
		t.Errorf("galleryHandler() wrong password redirect = %s, want error=incorrect_password", location)
	}
}

func TestViewHandlerWithVideoFile(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test video content
	testVideoData := []byte("fake video content for testing")

	// Create an encrypted test video file
	encFileName, err := encryptFileName("test_video.mp4", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	testFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testVideoData, testFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test video file: %v", err)
	}
	defer os.Remove(testFilePath)

	// Create request
	req, err := http.NewRequest("GET", "/view/"+encFileName, nil)
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
	viewHandler(rr, req)

	// Should return OK for video file
	if rr.Code != http.StatusOK {
		t.Errorf("viewHandler() video status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Check content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "video/mp4" {
		t.Errorf("viewHandler() video Content-Type = %s, want video/mp4", contentType)
	}
}

func TestViewHandlerWithPDFFile(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test PDF content
	testPDFData := []byte("%PDF-1.4 fake pdf content")

	// Create an encrypted test PDF file
	encFileName, err := encryptFileName("test_document.pdf", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	testFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testPDFData, testFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test PDF file: %v", err)
	}
	defer os.Remove(testFilePath)

	// Create request
	req, err := http.NewRequest("GET", "/view/"+encFileName, nil)
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
	viewHandler(rr, req)

	// Should return OK for PDF file
	if rr.Code != http.StatusOK {
		t.Errorf("viewHandler() PDF status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Check content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/pdf" {
		t.Errorf("viewHandler() PDF Content-Type = %s, want application/pdf", contentType)
	}
}

func TestUploadHandlerNoFiles(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test directory
	testDir := filepath.Join(galleryDir, "test_upload_empty")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	// Create request with no files
	req, err := http.NewRequest("POST", "/upload", strings.NewReader("currentDir=/test_upload_empty"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	uploadHandler(rr, req)

	// Should return bad request for no files
	if rr.Code != http.StatusBadRequest {
		t.Errorf("uploadHandler() no files status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestThumbnailHandlerDecryptionFailure(t *testing.T) {
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

	// Should redirect to login page for decryption failure (wrong password)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("thumbnailHandler() decryption failure status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Check redirect location
	location := rr.Header().Get("Location")
	if !strings.Contains(location, "error=incorrect_password") {
		t.Errorf("thumbnailHandler() decryption failure redirect = %s, want to contain error=incorrect_password", location)
	}
}

func TestIndexHandlerAlreadyLoggedIn(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create session with authenticated user
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = passwordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	indexHandler(rr, req)

	// Should redirect to gallery
	if rr.Code != http.StatusSeeOther {
		t.Errorf("indexHandler() already logged in status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/gallery/" {
		t.Errorf("indexHandler() already logged in redirect = %s, want /gallery/", location)
	}
}
