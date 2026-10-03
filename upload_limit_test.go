package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newUploadRequest builds an authenticated multipart upload of size bytes into dir
func newUploadRequest(t *testing.T, dir string, size int) *http.Request {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	if err := writer.WriteField("currentDir", "/"+dir); err != nil {
		t.Fatalf("Error writing form field: %v", err)
	}
	part, err := writer.CreateFormFile("file", "big.jpg")
	if err != nil {
		t.Fatalf("Error creating form file: %v", err)
	}
	part.Write(bytes.Repeat([]byte("a"), size))
	writer.Close()

	req, err := http.NewRequest("POST", "/upload", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	if err := session.Save(req, rr); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))
	return req
}

func TestUploadHandlerSizeLimit(t *testing.T) {
	// Not parallel: changes the global upload limit
	originalLimit := maxUploadBytes
	maxUploadBytes = 1 << 20 // 1 MB
	defer func() { maxUploadBytes = originalLimit }()

	dirName := "test_upload_limit"
	testDir := filepath.Join(galleryDir, dirName)
	os.MkdirAll(testDir, 0755)
	defer os.RemoveAll(testDir)
	defer os.RemoveAll(filepath.Join(thumbnailsDir, dirName))

	t.Run("Over limit is rejected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		uploadHandler(rr, newUploadRequest(t, dirName, 3<<20))

		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
		}
		if !strings.Contains(rr.Body.String(), "max 1 MB") {
			t.Errorf("body = %q, want it to mention the limit", rr.Body.String())
		}
		if files, _ := os.ReadDir(testDir); len(files) != 0 {
			t.Errorf("expected no files saved, found %d", len(files))
		}
	})

	t.Run("Under limit is accepted", func(t *testing.T) {
		rr := httptest.NewRecorder()
		uploadHandler(rr, newUploadRequest(t, dirName, 512<<10))

		if rr.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("file under the limit was rejected: %s", rr.Body.String())
		}
		if files, _ := os.ReadDir(testDir); len(files) != 1 {
			t.Errorf("expected 1 file saved, found %d", len(files))
		}
	})
}
