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

func TestRenameHandler(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name         string
		path         string
		newName      string
		currentDir   string
		createFile   bool
		createDir    bool
		expectStatus int
	}{
		{
			name:         "Rename file",
			path:         "test_file.txt",
			newName:      "renamed_file.txt",
			currentDir:   "/",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusSeeOther,
		},
		{
			name:         "Rename directory",
			path:         "test_dir",
			newName:      "renamed_dir",
			currentDir:   "/",
			createFile:   false,
			createDir:    true,
			expectStatus: http.StatusSeeOther,
		},
		{
			name:         "Empty new name",
			path:         "test_file.txt",
			newName:      "",
			currentDir:   "/",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Invalid characters in new name",
			path:         "test_file.txt",
			newName:      "invalid/name.txt",
			currentDir:   "/",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Non-existent file",
			path:         "nonexistent.txt",
			newName:      "new_name.txt",
			currentDir:   "/",
			createFile:   false,
			createDir:    false,
			expectStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testPath string
			var encryptedPath string

			if tt.createFile || tt.createDir {
				encFileName, err := encryptFileName(filepath.Base(tt.path), passwordHash)
				if err != nil {
					t.Fatalf("Failed to encrypt filename: %v", err)
				}

				testPath = filepath.Join(galleryDir, encFileName+encryptedExt)
				encryptedPath = encFileName + encryptedExt

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

			form := url.Values{}
			form.Add("path", encryptedPath)
			form.Add("newName", tt.newName)
			form.Add("currentDir", tt.currentDir)

			req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			session.Values["password_hash"] = passwordHash
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			rr = httptest.NewRecorder()
			renameHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("renameHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Verify rename actually happened for successful cases
			if tt.expectStatus == http.StatusSeeOther && tt.newName != "" && testPath != "" {
				// Verify old file no longer exists
				if _, err := os.Stat(testPath); !os.IsNotExist(err) {
					t.Error("renameHandler() original file still exists after rename")
				}

				// Find the new file by listing the directory
				files, err := os.ReadDir(galleryDir)
				if err != nil {
					t.Fatalf("Failed to read gallery directory: %v", err)
				}

				found := false
				for _, f := range files {
					encName := f.Name()
					if strings.HasSuffix(encName, encryptedExt) {
						decName, err := decryptFileName(strings.TrimSuffix(encName, encryptedExt), passwordHash)
						if err != nil {
							continue
						}
						if decName == tt.newName {
							found = true
							break
						}
					}
				}

				if !found {
					t.Errorf("renameHandler() renamed file with decrypted name '%s' not found", tt.newName)
				}
			}
		})
	}
}

func TestRenameHandlerUnauthenticated(t *testing.T) {
	form := url.Values{}
	form.Add("path", "test")
	form.Add("newName", "new_name")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	renameHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("renameHandler() unauthenticated status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("renameHandler() unauthenticated redirect = %s, want /", location)
	}
}

func TestRenameHandlerPathTraversal(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	tests := []struct {
		name    string
		path    string
		newName string
	}{
		{
			name:    "Path traversal in path",
			path:    "../../../etc/passwd",
			newName: "new_name",
		},
		{
			name:    "Path traversal in new name",
			path:    "test",
			newName: "../../../etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("path", tt.path)
			form.Add("newName", tt.newName)
			form.Add("currentDir", "/")

			req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			session.Values["password_hash"] = passwordHash
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			rr = httptest.NewRecorder()
			renameHandler(rr, req)

			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
				t.Errorf("renameHandler() path traversal status = %d, want %d or %d",
					rr.Code, http.StatusBadRequest, http.StatusNotFound)
			}
		})
	}
}

func TestRenameHandlerWithThumbnail(t *testing.T) {
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

	// Rename the file
	form := url.Values{}
	form.Add("path", encFileName+encryptedExt)
	form.Add("newName", "renamed_image.jpg")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = passwordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	renameHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("renameHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Verify both main file and thumbnail were renamed
	if _, err := os.Stat(mainFilePath); !os.IsNotExist(err) {
		t.Error("renameHandler() original main file still exists after rename")
	}

	if _, err := os.Stat(thumbnailPath); !os.IsNotExist(err) {
		t.Error("renameHandler() original thumbnail still exists after rename")
	}

	// Find the renamed file in the gallery directory
	files, err := os.ReadDir(galleryDir)
	if err != nil {
		t.Fatalf("Failed to read gallery directory: %v", err)
	}

	foundMain := false
	for _, f := range files {
		encName := f.Name()
		if strings.HasSuffix(encName, encryptedExt) {
			decName, err := decryptFileName(strings.TrimSuffix(encName, encryptedExt), passwordHash)
			if err != nil {
				continue
			}
			if decName == "renamed_image.jpg" {
				foundMain = true
				// Also check thumbnail exists
				thumbPath := filepath.Join(thumbnailsDir, encName)
				if _, err := os.Stat(thumbPath); os.IsNotExist(err) {
					t.Error("renameHandler() renamed thumbnail does not exist")
				}
				break
			}
		}
	}

	if !foundMain {
		t.Error("renameHandler() renamed main file not found")
	}
}

func TestRenameHandlerDuplicateName(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create two test files with the same plaintext name
	// Since encryption is non-deterministic, they will have different encrypted names
	encFileName1, err := encryptFileName("same_name.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	encFileName2, err := encryptFileName("same_name.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	// They should be different due to random IV
	if encFileName1 == encFileName2 {
		t.Fatal("Two encryptions of the same name should produce different results")
	}

	file1Path := filepath.Join(galleryDir, encFileName1+encryptedExt)
	err = encryptAndSaveFile([]byte("content1"), file1Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}

	file2Path := filepath.Join(galleryDir, encFileName2+encryptedExt)
	err = encryptAndSaveFile([]byte("content2"), file2Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Rename file1 to "same_name.txt" - this should succeed because
	// the encrypted name will be different from file2's encrypted name
	form := url.Values{}
	form.Add("path", encFileName1+encryptedExt)
	form.Add("newName", "same_name.txt")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = passwordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	renameHandler(rr, req)

	// Should succeed - duplicate plaintext names are allowed
	if rr.Code != http.StatusSeeOther {
		t.Errorf("renameHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Both files should still exist (with different encrypted names)
	if _, err := os.Stat(file2Path); os.IsNotExist(err) {
		t.Error("renameHandler() second file was affected")
	}
}

func TestRenameHandlerExistingEncryptedName(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create a file
	encFileName1, err := encryptFileName("file1.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	file1Path := filepath.Join(galleryDir, encFileName1+encryptedExt)
	err = encryptAndSaveFile([]byte("content1"), file1Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}

	// Create another file with a known encrypted name
	encFileName2, err := encryptFileName("file2.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	file2Path := filepath.Join(galleryDir, encFileName2+encryptedExt)
	err = encryptAndSaveFile([]byte("content2"), file2Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Try to rename file1 to a name that would result in file2's encrypted name
	// This is unlikely to happen naturally, but we test the collision check
	// by trying to rename to a name that already has an encrypted version

	// First, let's test that renaming to file2.txt succeeds because
	// the encryption produces a different result
	form := url.Values{}
	form.Add("path", encFileName1+encryptedExt)
	form.Add("newName", "file2.txt")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/rename", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = passwordHash
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	renameHandler(rr, req)

	// Should succeed because encryption is non-deterministic
	if rr.Code != http.StatusSeeOther {
		t.Errorf("renameHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Both files should exist
	if _, err := os.Stat(file2Path); os.IsNotExist(err) {
		t.Error("renameHandler() file2 was affected")
	}
}