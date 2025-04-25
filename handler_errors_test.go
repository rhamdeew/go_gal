package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLoginHandlerErrors(t *testing.T) {
	// Test with empty password
	form := url.Values{}
	form.Add("password", "")
	req, err := http.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(loginHandler)

	handler.ServeHTTP(rr, req)

	// Should return OK but with error message in the template
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Should contain error message
	if !strings.Contains(rr.Body.String(), "Password required") {
		t.Error("Expected error message in response")
	}
}

func TestGalleryHandlerErrors(t *testing.T) {
	// Test case: not authenticated
	req1, err := http.NewRequest("GET", "/gallery/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(galleryHandler)

	// Add URL vars
	req1 = SetURLVars(req1, map[string]string{"path": ""})

	handler.ServeHTTP(rr1, req1)

	// Should redirect to login
	if status := rr1.Code; status != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should redirect: got %v want %v", status, http.StatusSeeOther)
	}

	// Test case: authenticated but invalid path
	req2, err := http.NewRequest("GET", "/gallery/invalid_path", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a session
	rr2 := httptest.NewRecorder()
	session, _ := store.Get(req2, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	err = session.Save(req2, rr2)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req2.Header.Add("Cookie", rr2.Header().Get("Set-Cookie"))

	// Add URL vars
	req2 = SetURLVars(req2, map[string]string{"path": "invalid_path"})

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should return OK but with error message
	if status := rr2.Code; status != http.StatusOK {
		t.Errorf("Expected OK status with error message: got %v", status)
	}

	// Check for error message
	if !strings.Contains(rr2.Body.String(), "Path does not exist") {
		t.Error("Expected 'Path does not exist' error in response")
	}
}

func TestViewHandlerErrors(t *testing.T) {
	// Test case: not authenticated
	req1, err := http.NewRequest("GET", "/view/somefile", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr1 := httptest.NewRecorder()

	// Add URL vars
	req1 = SetURLVars(req1, map[string]string{"path": "somefile"})

	handler := http.HandlerFunc(viewHandler)
	handler.ServeHTTP(rr1, req1)

	// Should redirect to login
	if status := rr1.Code; status != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should redirect: got %v want %v", status, http.StatusSeeOther)
	}

	// Test case: authenticated but file not found
	req2, err := http.NewRequest("GET", "/view/nonexistent", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Create a session
	rr2 := httptest.NewRecorder()
	session, _ := store.Get(req2, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	err = session.Save(req2, rr2)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req2.Header.Add("Cookie", rr2.Header().Get("Set-Cookie"))

	// Add URL vars
	req2 = SetURLVars(req2, map[string]string{"path": "nonexistent"})

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should return NotFound
	if status := rr2.Code; status != http.StatusNotFound {
		t.Errorf("Expected NotFound for nonexistent file: got %v", status)
	}
}

func TestUploadHandlerErrors(t *testing.T) {
	// Test case: not authenticated
	req1, err := http.NewRequest("POST", "/upload", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(uploadHandler)

	handler.ServeHTTP(rr1, req1)

	// Should redirect to login
	if status := rr1.Code; status != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should redirect: got %v want %v", status, http.StatusSeeOther)
	}

	// Test case: authenticated but invalid form
	req2, err := http.NewRequest("POST", "/upload", strings.NewReader("invalid form data"))
	if err != nil {
		t.Fatal(err)
	}

	// Create a session
	rr2 := httptest.NewRecorder()
	session, _ := store.Get(req2, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	err = session.Save(req2, rr2)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req2.Header.Add("Cookie", rr2.Header().Get("Set-Cookie"))
	req2.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW")

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should return BadRequest
	if status := rr2.Code; status != http.StatusBadRequest {
		t.Errorf("Expected BadRequest for invalid form: got %v", status)
	}
}

func TestCreateDirHandlerErrors(t *testing.T) {
	// Test case: not authenticated
	req1, err := http.NewRequest("POST", "/createdir", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(createDirHandler)

	handler.ServeHTTP(rr1, req1)

	// Should redirect to login
	if status := rr1.Code; status != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should redirect: got %v want %v", status, http.StatusSeeOther)
	}

	// Test case: authenticated but missing directory name
	form := url.Values{}
	form.Add("currentDir", "/")
	form.Add("dirName", "")

	req2, err := http.NewRequest("POST", "/createdir", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Create a session
	rr2 := httptest.NewRecorder()
	session, _ := store.Get(req2, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	err = session.Save(req2, rr2)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req2.Header.Add("Cookie", rr2.Header().Get("Set-Cookie"))

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should return BadRequest
	if status := rr2.Code; status != http.StatusBadRequest {
		t.Errorf("Expected BadRequest for missing directory name: got %v", status)
	}
}
