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

func TestMoveHandler(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create a subdirectory for testing moves
	subDirEnc, err := encryptFileName("subdir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	subDirPath := filepath.Join(galleryDir, subDirEnc+encryptedExt)
	err = os.MkdirAll(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	tests := []struct {
		name         string
		sourcePath   string
		targetDir    string
		currentDir   string
		createFile   bool
		createDir    bool
		expectStatus int
	}{
		{
			name:         "Move file to subdirectory",
			sourcePath:   "test_file.txt",
			targetDir:    subDirEnc + encryptedExt,
			currentDir:   "/",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusSeeOther,
		},
		{
			name:         "Move directory to subdirectory",
			sourcePath:   "test_dir",
			targetDir:    subDirEnc + encryptedExt,
			currentDir:   "/",
			createFile:   false,
			createDir:    true,
			expectStatus: http.StatusSeeOther,
		},
		{
			name:         "Move file to root",
			sourcePath:   "subdir/root_file.txt",
			targetDir:    "",
			currentDir:   "/subdir",
			createFile:   true,
			createDir:    false,
			expectStatus: http.StatusSeeOther,
		},
		{
			name:         "Empty source path",
			sourcePath:   "",
			targetDir:    "",
			currentDir:   "/",
			createFile:   false,
			createDir:    false,
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Non-existent source",
			sourcePath:   "nonexistent.txt",
			targetDir:    "",
			currentDir:   "/",
			createFile:   false,
			createDir:    false,
			expectStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var testPath string
			var encryptedSourcePath string
			var encFileName string

			if tt.createFile || tt.createDir {
				encFileName, err = encryptFileName(filepath.Base(tt.sourcePath), passwordHash)
				if err != nil {
					t.Fatalf("Failed to encrypt filename: %v", err)
				}

				dirPath := filepath.Dir(tt.sourcePath)
				if dirPath != "." {
					// Source is in a subdirectory
					testPath = filepath.Join(galleryDir, dirPath, encFileName+encryptedExt)
					encryptedSourcePath = filepath.Join(dirPath, encFileName+encryptedExt)
				} else {
					testPath = filepath.Join(galleryDir, encFileName+encryptedExt)
					encryptedSourcePath = encFileName + encryptedExt
				}

				// Ensure parent directory exists
				err = os.MkdirAll(filepath.Dir(testPath), 0755)
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
				encryptedSourcePath = tt.sourcePath
			}

			form := url.Values{}
			form.Add("sourcePath", encryptedSourcePath)
			form.Add("targetDir", tt.targetDir)
			form.Add("currentDir", tt.currentDir)

			req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			rr = httptest.NewRecorder()
			moveHandler(rr, req)

			if rr.Code != tt.expectStatus {
				t.Errorf("moveHandler() status = %d, want %d", rr.Code, tt.expectStatus)
			}

			// Verify move actually happened for successful cases
			if tt.expectStatus == http.StatusSeeOther && (tt.createFile || tt.createDir) && testPath != "" {
				// Verify original no longer exists
				if _, err := os.Stat(testPath); !os.IsNotExist(err) {
					t.Error("moveHandler() original item still exists after move")
				}

				// Determine target directory
				targetGalleryDir := galleryDir
				if tt.targetDir != "" {
					targetGalleryDir = filepath.Join(galleryDir, tt.targetDir)
				}

				// Verify file exists in target
				if encFileName != "" {
					targetPath := filepath.Join(targetGalleryDir, encFileName+encryptedExt)
					if _, err := os.Stat(targetPath); os.IsNotExist(err) {
						t.Errorf("moveHandler() moved item does not exist at %s", targetPath)
					}
				}
			}
		})
	}
}

func TestMoveHandlerUnauthenticated(t *testing.T) {
	form := url.Values{}
	form.Add("sourcePath", "test")
	form.Add("targetDir", "")
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	moveHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("moveHandler() unauthenticated status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	location := rr.Header().Get("Location")
	if location != "/" {
		t.Errorf("moveHandler() unauthenticated redirect = %s, want /", location)
	}
}

func TestMoveHandlerPathTraversal(t *testing.T) {
	tests := []struct {
		name       string
		sourcePath string
		targetDir  string
	}{
		{
			name:       "Path traversal in source",
			sourcePath: "../../../etc/passwd",
			targetDir:  "",
		},
		{
			name:       "Path traversal in target",
			sourcePath: "test",
			targetDir:  "../../../etc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := url.Values{}
			form.Add("sourcePath", tt.sourcePath)
			form.Add("targetDir", tt.targetDir)
			form.Add("currentDir", "/")

			req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rr := httptest.NewRecorder()
			session, _ := store.Get(req, "gallery-session")
			session.Values["authenticated"] = true
			err = session.Save(req, rr)
			if err != nil {
				t.Fatalf("Error saving session: %v", err)
			}
			req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

			rr = httptest.NewRecorder()
			moveHandler(rr, req)

			if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
				t.Errorf("moveHandler() path traversal status = %d, want %d or %d",
					rr.Code, http.StatusBadRequest, http.StatusNotFound)
			}
		})
	}
}

func TestMoveHandlerDirectoryIntoItself(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create a directory with a subdirectory
	parentDirEnc, err := encryptFileName("parent_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt parent directory name: %v", err)
	}
	parentDirPath := filepath.Join(galleryDir, parentDirEnc+encryptedExt)
	err = os.MkdirAll(parentDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create parent directory: %v", err)
	}

	// Create a subdirectory
	subDirEnc, err := encryptFileName("sub_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	subDirPath := filepath.Join(parentDirPath, subDirEnc+encryptedExt)
	err = os.MkdirAll(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Try to move parent into its own subdirectory
	form := url.Values{}
	form.Add("sourcePath", parentDirEnc+encryptedExt)
	form.Add("targetDir", filepath.Join(parentDirEnc+encryptedExt, subDirEnc+encryptedExt))
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	moveHandler(rr, req)

	// Should fail with bad request
	if rr.Code != http.StatusBadRequest {
		t.Errorf("moveHandler() move into self status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	// Verify directory still exists
	if _, err := os.Stat(parentDirPath); os.IsNotExist(err) {
		t.Error("moveHandler() directory was moved despite invalid target")
	}
}

func TestMoveHandlerWithThumbnail(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create subdirectory for target
	subDirEnc, err := encryptFileName("target_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	subDirPath := filepath.Join(galleryDir, subDirEnc+encryptedExt)
	err = os.MkdirAll(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

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

	// Move the file
	form := url.Values{}
	form.Add("sourcePath", encFileName+encryptedExt)
	form.Add("targetDir", subDirEnc+encryptedExt)
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	moveHandler(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("moveHandler() status = %d, want %d", rr.Code, http.StatusSeeOther)
	}

	// Verify both main file and thumbnail were moved
	if _, err := os.Stat(mainFilePath); !os.IsNotExist(err) {
		t.Error("moveHandler() original main file still exists after move")
	}

	if _, err := os.Stat(thumbnailPath); !os.IsNotExist(err) {
		t.Error("moveHandler() original thumbnail still exists after move")
	}

	// Verify new files exist in target directory
	newMainPath := filepath.Join(subDirPath, encFileName+encryptedExt)
	if _, err := os.Stat(newMainPath); os.IsNotExist(err) {
		t.Error("moveHandler() moved main file does not exist in target directory")
	}

	newThumbnailPath := filepath.Join(thumbnailsDir, subDirEnc+encryptedExt, encFileName+encryptedExt)
	if _, err := os.Stat(newThumbnailPath); os.IsNotExist(err) {
		t.Error("moveHandler() moved thumbnail does not exist in target directory")
	}
}

func TestMoveHandlerDuplicateName(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create subdirectory for target
	subDirEnc, err := encryptFileName("target_dir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	subDirPath := filepath.Join(galleryDir, subDirEnc+encryptedExt)
	err = os.MkdirAll(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create a test file with a specific encrypted name
	encFileName, err := encryptFileName("test_file.txt", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt filename: %v", err)
	}

	// File in root
	file1Path := filepath.Join(galleryDir, encFileName+encryptedExt)
	err = encryptAndSaveFile([]byte("content1"), file1Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}

	// File with same encrypted name in subdirectory
	file2Path := filepath.Join(subDirPath, encFileName+encryptedExt)
	err = encryptAndSaveFile([]byte("content2"), file2Path, passwordHash)
	if err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Try to move file from root to subdirectory (would create duplicate encrypted name)
	form := url.Values{}
	form.Add("sourcePath", encFileName+encryptedExt)
	form.Add("targetDir", subDirEnc+encryptedExt)
	form.Add("currentDir", "/")

	req, err := http.NewRequest("POST", "/move", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	rr = httptest.NewRecorder()
	moveHandler(rr, req)

	// Should fail with bad request because file already exists
	if rr.Code != http.StatusBadRequest {
		t.Errorf("moveHandler() duplicate name status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	// Verify original file still exists
	if _, err := os.Stat(file1Path); os.IsNotExist(err) {
		t.Error("moveHandler() original file was deleted on failed move")
	}
}