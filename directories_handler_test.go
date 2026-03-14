package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestGetDirectoriesHandler(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test directory structure
	dir1Enc, err := encryptFileName("dir1", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}
	dir1Path := filepath.Join(galleryDir, dir1Enc+encryptedExt)
	err = os.MkdirAll(dir1Path, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Create subdirectory
	subDirEnc, err := encryptFileName("subdir", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	subDirPath := filepath.Join(dir1Path, subDirEnc+encryptedExt)
	err = os.MkdirAll(subDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create another top-level directory
	dir2Enc, err := encryptFileName("dir2", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}
	dir2Path := filepath.Join(galleryDir, dir2Enc+encryptedExt)
	err = os.MkdirAll(dir2Path, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	req, err := http.NewRequest("GET", "/api/directories", nil)
	if err != nil {
		t.Fatal(err)
	}

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
	getDirectoriesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("getDirectoriesHandler() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var directories []map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &directories)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should have root + 3 directories
	if len(directories) < 4 {
		t.Errorf("getDirectoriesHandler() returned %d directories, expected at least 4", len(directories))
	}

	// Check that root is first
	if directories[0]["path"] != "" {
		t.Errorf("getDirectoriesHandler() first directory path = %s, expected empty string for root", directories[0]["path"])
	}
	if directories[0]["displayName"] != "/ (Root)" {
		t.Errorf("getDirectoriesHandler() first directory displayName = %s, expected '/ (Root)'", directories[0]["displayName"])
	}

	// Check content type
	if rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("getDirectoriesHandler() Content-Type = %s, expected application/json", rr.Header().Get("Content-Type"))
	}
}

func TestGetDirectoriesHandlerUnauthenticated(t *testing.T) {
	req, err := http.NewRequest("GET", "/api/directories", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	getDirectoriesHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("getDirectoriesHandler() unauthenticated status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestGetDirectoriesHandlerWithExclusion(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Create test directory structure
	parentDirEnc, err := encryptFileName("parent", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}
	parentDirPath := filepath.Join(galleryDir, parentDirEnc+encryptedExt)
	err = os.MkdirAll(parentDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Create subdirectory
	childDirEnc, err := encryptFileName("child", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt subdirectory name: %v", err)
	}
	childDirPath := filepath.Join(parentDirPath, childDirEnc+encryptedExt)
	err = os.MkdirAll(childDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create another directory
	otherDirEnc, err := encryptFileName("other", passwordHash)
	if err != nil {
		t.Fatalf("Failed to encrypt directory name: %v", err)
	}
	otherDirPath := filepath.Join(galleryDir, otherDirEnc+encryptedExt)
	err = os.MkdirAll(otherDirPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create directory: %v", err)
	}

	// Request directories excluding the parent directory
	req, err := http.NewRequest("GET", "/api/directories?itemPath="+parentDirEnc+encryptedExt, nil)
	if err != nil {
		t.Fatal(err)
	}

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
	getDirectoriesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("getDirectoriesHandler() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var directories []map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &directories)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify parent and child are not in the list
	for _, dir := range directories {
		if dir["path"] == parentDirEnc+encryptedExt {
			t.Error("getDirectoriesHandler() included the excluded directory")
		}
		if dir["path"] == filepath.Join(parentDirEnc+encryptedExt, childDirEnc+encryptedExt) {
			t.Error("getDirectoriesHandler() included subdirectory of excluded directory")
		}
	}

	// Verify other directory is still present
	foundOther := false
	for _, dir := range directories {
		if dir["path"] == otherDirEnc+encryptedExt {
			foundOther = true
			break
		}
	}
	if !foundOther {
		t.Error("getDirectoriesHandler() did not include other directory")
	}
}

func TestGetDirectoriesHandlerEmpty(t *testing.T) {
	passwordHash := hashPassword("testpassword")

	// Ensure gallery directory exists but is empty (except for test files from other tests)
	req, err := http.NewRequest("GET", "/api/directories", nil)
	if err != nil {
		t.Fatal(err)
	}

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
	getDirectoriesHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("getDirectoriesHandler() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var directories []map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &directories)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Should always have at least root
	if len(directories) < 1 {
		t.Error("getDirectoriesHandler() should always return at least root directory")
	}

	// Root should be first
	if directories[0]["path"] != "" {
		t.Error("getDirectoriesHandler() root path should be empty string")
	}
}