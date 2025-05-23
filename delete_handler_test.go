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

func TestDeleteHandler(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		path         string
		currentDir   string
		createFile   bool
		createDir    bool
		expectStatus int
		expectRedirect string
	}{
		{
			name:         "Delete file",
			path:         "test_file",
			currentDir:   "/",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusSeeOther,
			expectRedirect: "/gallery/",
		},
		{
			name:         "Delete directory",
			path:         "test_dir",
			currentDir:   "/",
			createFile:   false,
			createDir:    true,
			expectStatus: http.StatusSeeOther,
			expectRedirect: "/gallery/",
		},
		{
			name:         "Delete from subdirectory",
			path:         "subdir/test_file",
			currentDir:   "/subdir",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusSeeOther,
			expectRedirect: "/gallery/subdir/",
		},
		{
			name:         "Delete non-existent file",
			path:         "nonexistent",
			currentDir:   "/",
			createFile:   false,
			createDir:    false,
			expectStatus: http.StatusNotFound,
			expectRedirect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test file or directory
			var testPath string
			var encryptedPath string
			if tt.createFile || tt.createDir {
				// Encrypt the filename
				baseName := filepath.Base(tt.path)
				dirPath := filepath.Dir(tt.path)
				if dirPath == "." {
					dirPath = ""
				}

				encFileName, err := encryptFileName(baseName, passwordHash)
				if err != nil {
					t.Fatalf("Failed to encrypt filename: %v", err)
				}

				testPath = filepath.Join(galleryDir, dirPath, encFileName+encryptedExt)

				// The encrypted path for the form submission
				if dirPath != "" {
					encryptedPath = filepath.Join(dirPath, encFileName+encryptedExt)
				} else {
					encryptedPath = encFileName + encryptedExt
				}

				// Create parent directory if needed
				parentDir := filepath.Dir(testPath)
				err = os.MkdirAll(parentDir, 0755)
				if err != nil {
					t.Fatalf("Failed to create parent directory: %v", err)
				}

				if tt.createFile {
					err = encryptAndSaveFile([]byte("test content"), testPath, passwordHash)
					if err != nil {
						t.Fatalf("Failed to create test file: %v", err)
					}
				} else if tt.createDir {
					err = os.MkdirAll(testPath, 0755)
					if err != nil {
						t.Fatalf("Failed to create test directory: %v", err)
					}
				}
			} else {
				encryptedPath = tt.path
			}

			// Create form data - use encrypted path for deletion
			form := url.Values{}
			form.Add("path", encryptedPath)
			form.Add("currentDir", tt.currentDir)

			// Create request
			req, err := http.NewRequest("POST", "/delete", strings.NewReader(form.Encode()))
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
			deleteHandler(rr, req)

			// Check response status
			if rr.Code != tt.expectStatus {
				t.Errorf("deleteHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Check redirect location for successful deletions
			if tt.expectStatus == http.StatusSeeOther {
				location := rr.Header().Get("Location")
				if location != tt.expectRedirect {
					t.Errorf("deleteHandler() redirect = %s, want %s", location, tt.expectRedirect)
				}

				// Verify file/directory was actually deleted
				if testPath != "" {
					if _, err := os.Stat(testPath); !os.IsNotExist(err) {
						t.Errorf("deleteHandler() file/directory still exists after deletion")
					}
				}
			}
		})
	}
}

func TestDeleteHandlerUnauthenticated(t *testing.T) {
	form := url.Values{}
	form.Add("path", "test")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/delete", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	deleteHandler(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusSeeOther {
		t.Errorf("deleteHandler() unauthenticated status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("deleteHandler() unauthenticated redirect = %s, want /", location)
	}
}

func TestDeleteHandlerInvalidPath(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name       string
		path       string
		currentDir string
	}{
		{
			name:       "Empty path",
			path:       "",
			currentDir: "/",
		},
		{
			name:       "Path traversal attempt",
			path:       "../../../etc/passwd",
			currentDir: "/",
		},
		{
			name:       "Absolute path attempt",
			path:       "/etc/passwd",
			currentDir: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("path", tt.path)
			form.Add("currentDir", tt.currentDir)

			req, err := http.NewRequest("POST", "/delete", strings.NewReader(form.Encode()))
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
			deleteHandler(rr, req)

			// Should handle gracefully (bad request or not found)
			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
				t.Errorf("deleteHandler() invalid path status = %d, want %d or %d",
					rr.Code, http.StatusBadRequest, http.StatusNotFound)
			}
		})
	}
}

func TestDeleteHandlerWithThumbnail(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test image file
	testImageData := createTestJPEG()
	encFileName, err := encryptFileName("test_image.jpg", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	// Create main file
	mainFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testImageData, mainFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create thumbnail
	err = os.MkdirAll(thumbnailsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create thumbnails directory: %v", err)
	}

	thumbnailPath := filepath.Join(thumbnailsDir, encFileName+encryptedExt)
	err = encryptAndSaveFile(testImageData, thumbnailPath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test thumbnail: %v", err)
	}

	// Create form data
	form := url.Values{}
	form.Add("path", encFileName+encryptedExt)
	form.Add("currentDir", "/")

	// Create request
	req, err := http.NewRequest("POST", "/delete", strings.NewReader(form.Encode()))
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
	deleteHandler(rr, req)

	// Check response
	if rr.Code != http.StatusSeeOther {
		t.Errorf("deleteHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Verify both main file and thumbnail were deleted
	if _, err := os.Stat(mainFilePath); !os.IsNotExist(err) {
		t.Error("deleteHandler() main file still exists after deletion")
	}

	if _, err := os.Stat(thumbnailPath); !os.IsNotExist(err) {
		t.Error("deleteHandler() thumbnail still exists after deletion")
	}
}

func TestDeleteHandlerDirectoryWithContents(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test directory structure
	encDirName, err := encryptFileName("test_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}

	testDirPath := filepath.Join(galleryDir, encDirName+encryptedExt)
	err = os.MkdirAll(testDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create a file inside the directory
	encFileName, err := encryptFileName("inner_file.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	innerFilePath := filepath.Join(testDirPath, encFileName+encryptedExt)
	err = encryptAndSaveFile([]byte("inner content"), innerFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create inner file: %v", err)
	}

	// Create corresponding thumbnail directory structure
	err = os.MkdirAll(thumbnailsDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create thumbnails directory: %v", err)
	}

	thumbnailDirPath := filepath.Join(thumbnailsDir, encDirName+encryptedExt)
	err = os.MkdirAll(thumbnailDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create thumbnail directory: %v", err)
	}

	// Create form data
	form := url.Values{}
	form.Add("path", encDirName+encryptedExt)
	form.Add("currentDir", "/")

	// Create request
	req, err := http.NewRequest("POST", "/delete", strings.NewReader(form.Encode()))
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
	deleteHandler(rr, req)

	// Check response
	if rr.Code != http.StatusSeeOther {
		t.Errorf("deleteHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Verify directory and its contents were deleted recursively
	if _, err := os.Stat(testDirPath); !os.IsNotExist(err) {
		t.Error("deleteHandler() directory still exists after deletion")
	}

	if _, err := os.Stat(innerFilePath); !os.IsNotExist(err) {
		t.Error("deleteHandler() inner file still exists after deletion")
	}

	if _, err := os.Stat(thumbnailDirPath); !os.IsNotExist(err) {
		t.Error("deleteHandler() thumbnail directory still exists after deletion")
	}
}