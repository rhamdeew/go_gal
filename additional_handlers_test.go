package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoginHandlerEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		password     string
		expectStatus int
		expectError  bool
	}{
		{
			name:         "Empty password",
			password:     "",
			expectStatus: http.StatusOK, // Should render login page with error
			expectError:  true,
		},
		{
			name:         "Valid password",
			password:     "testpassword",
			expectStatus: http.StatusSeeOther,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("password", tt.password)
			req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			loginHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("loginHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}
		})
	}
}

func TestGalleryHandlerEdgeCases(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		path         string
		setupDir     bool
		expectStatus int
	}{
		{
			name:         "Root directory",
			path:         "",
			setupDir:     false,
			expectStatus: http.StatusOK,
		},
		{
			name:         "Non-existent directory",
			path:         "nonexistent",
			setupDir:     false,
			expectStatus: http.StatusOK, // Should render with error
		},
		{
			name:         "Invalid path traversal",
			path:         "../../../etc",
			setupDir:     false,
			expectStatus: http.StatusOK, // Should render with error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/gallery/"+tt.path, nil)
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
			galleryHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("galleryHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}
		})
	}
}

func TestViewHandlerEdgeCases(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		path         string
		createFile   bool
		expectStatus int
	}{
		{
			name:         "Empty path",
			path:         "",
			createFile:   false,
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Non-existent file",
			path:         "nonexistent",
			createFile:   false,
			expectStatus: http.StatusNotFound,
		},
		{
			name:         "Path traversal attempt",
			path:         "../../../etc/passwd",
			createFile:   false,
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/view/"+tt.path, nil)
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
			viewHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("viewHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}
		})
	}
}

func TestUploadHandlerMultipleFiles(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test directory
	testDir := filepath.Join(galleryDir, "test_upload_multi")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	// Create test data
	testContent1 := []byte("test file content 1")
	testContent2 := []byte("test file content 2")

	// Create a multipart form with multiple files
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add current directory field
	field, err := writer.CreateFormField("currentDir")
	if err != nil {
		t.Fatalf("Error creating form field: %v", err)
	}
	field.Write([]byte("/test_upload_multi"))

	// Add first test file
	part1, err := writer.CreateFormFile("files", "test1.txt")
	if err != nil {
		t.Fatalf("Error creating form file: %v", err)
	}
	part1.Write(testContent1)

	// Add second test file
	part2, err := writer.CreateFormFile("files", "test2.txt")
	if err != nil {
		t.Fatalf("Error creating form file: %v", err)
	}
	part2.Write(testContent2)

	writer.Close()

	// Create the request
	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Create session for the request
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

	// Check status code
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("uploadHandler() returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	// Check if files exist in directory (encrypted)
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("Error reading test directory: %v", err)
	}

	encryptedFileCount := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), encryptedExt) {
			encryptedFileCount++
		}
	}

	if encryptedFileCount != 2 {
		t.Errorf("Expected 2 encrypted files, found %d", encryptedFileCount)
	}
}

func TestUploadHandlerEdgeCases(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		currentDir   string
		expectStatus int
	}{
		{
			name:         "Non-existent directory",
			currentDir:   "/nonexistent",
			expectStatus: http.StatusNotFound,
		},
		{
			name:         "Path traversal attempt",
			currentDir:   "../../../etc",
			expectStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a multipart form with a file
			body := &bytes.Buffer{}
			writer := multipart.NewWriter(body)

			// Add current directory field
			field, err := writer.CreateFormField("currentDir")
			if err != nil {
				t.Fatalf("Error creating form field: %v", err)
			}
			field.Write([]byte(tt.currentDir))

			// Add test file
			part, err := writer.CreateFormFile("file", "test.txt")
			if err != nil {
				t.Fatalf("Error creating form file: %v", err)
			}
			part.Write([]byte("test content"))
			writer.Close()

			// Create the request
			req, err := http.NewRequest("POST", "/upload", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", writer.FormDataContentType())

			// Create session for the request
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

			if rr.Code != tt.expectStatus {
				t.Errorf("uploadHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}
		})
	}
}

func TestIndexHandlerWithError(t *testing.T) {
	req, err := http.NewRequest("GET", "/?error=incorrect_password", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	indexHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("indexHandler() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Check that the response contains the error message
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "Incorrect password") {
		t.Error("indexHandler() should display error message for incorrect password")
	}
}

func TestLogoutHandlerComplete(t *testing.T) {
	// First create a session
	req, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create session
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = "somehash"
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	// Reset recorder and serve logout request
	rr = httptest.NewRecorder()
	logoutHandler(rr, req)

	// Check redirect
	if rr.Code != http.StatusSeeOther {
		t.Errorf("logoutHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("logoutHandler() redirect = %s, want /", location)
	}
}