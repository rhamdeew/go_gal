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

func TestUploadHandler(t *testing.T) {
	// Create test directory
	testDir := filepath.Join(galleryDir, "test_upload")
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)

	// Create test data
	testContent := []byte("test file content")
	passwordHash := hashPassword("testpassword")

	// Create a multipart form with a file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add current directory field
	field, err := writer.CreateFormField("currentDir")
	if err != nil {
		t.Fatalf("Error creating form field: %v", err)
	}
	field.Write([]byte("/test_upload"))

	// Add test file
	part, err := writer.CreateFormFile("file", "test.txt")
	if err != nil {
		t.Fatalf("Error creating form file: %v", err)
	}
	part.Write(testContent)
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
	handler := http.HandlerFunc(uploadHandler)
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	// Check if file exists in directory (encrypted)
	files, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("Error reading test directory: %v", err)
	}

	found := false
	for _, file := range files {
		if strings.HasSuffix(file.Name(), encryptedExt) {
			found = true
			break
		}
	}

	if !found {
		t.Error("Uploaded file not found in test directory")
	}
}

func TestViewHandler(t *testing.T) {
	// Create test directory and file
	passwordHash := hashPassword("testpassword")
	testContent := []byte("test file for viewing")
	fileName := "testview.txt"

	// Create an encrypted filename
	encFileName, err := encryptFileName(fileName, passwordHash)
	if err != nil {
		t.Fatalf("Error encrypting filename: %v", err)
	}

	testFilePath := filepath.Join(galleryDir, encFileName+encryptedExt)

	// Create encrypted file
	err = encryptAndSaveFile(testContent, testFilePath, passwordHash)
	if err != nil {
		t.Fatalf("Error creating test file: %v", err)
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

	// Set up router to handle path variables
	router := http.NewServeMux()
	router.HandleFunc("/view/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/view/")
		r = SetURLVars(r, map[string]string{"path": path})
		viewHandler(w, r)
	})

	// Reset recorder and serve request
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Check response
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	responseBody, _ := io.ReadAll(rr.Body)
	if !bytes.Equal(responseBody, testContent) {
		t.Errorf("handler returned unexpected body: got %v bytes, want %v bytes",
			len(responseBody), len(testContent))
	}
}

func TestCreateDirHandler(t *testing.T) {
	// Create test directory
	testParentDir := filepath.Join(galleryDir, "test_parent_dir")
	os.MkdirAll(testParentDir, 0755)
	defer os.RemoveAll(testParentDir)

	passwordHash := hashPassword("testpassword")
	dirName := "test_new_directory"

	// Create form data
	form := url.Values{}
	form.Add("currentDir", "/test_parent_dir")
	form.Add("dirName", dirName)

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
	handler := http.HandlerFunc(createDirHandler)
	handler.ServeHTTP(rr, req)

	// Check status code
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	// Check if directory was created with any encrypted name ending with .enc
	foundEncryptedDir := false
	files, err := os.ReadDir(testParentDir)
	if err != nil {
		t.Fatalf("Error reading test parent directory: %v", err)
	}

	for _, file := range files {
		if file.IsDir() && strings.HasSuffix(file.Name(), encryptedExt) {
			// Try to decrypt the name to verify it's the correct directory
			encName := strings.TrimSuffix(file.Name(), encryptedExt)
			decryptedName, err := decryptFileName(encName, passwordHash)
			if err == nil && decryptedName == dirName {
				foundEncryptedDir = true
				break
			}
		}
	}

	if !foundEncryptedDir {
		t.Errorf("Directory with encrypted name for '%s' not found in %s", dirName, testParentDir)
	}
}
