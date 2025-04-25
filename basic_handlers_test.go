package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIndexHandler(t *testing.T) {
	// Test case: not authenticated
	req1, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(indexHandler)

	handler.ServeHTTP(rr1, req1)

	// Should return OK with login page
	if status := rr1.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Test case: authenticated
	req2, err := http.NewRequest("GET", "/", nil)
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

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	handler.ServeHTTP(rr2, req2)

	// Should redirect to gallery
	if status := rr2.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	if loc := rr2.Header().Get("Location"); loc != "/gallery/" {
		t.Errorf("handler returned wrong redirect location: got %v want %v", loc, "/gallery/")
	}
}

func TestLogoutHandler(t *testing.T) {
	// Create a request
	req, err := http.NewRequest("GET", "/logout", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set up an authenticated session
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")
	err = session.Save(req, rr)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))

	// Reset the response recorder
	rr = httptest.NewRecorder()

	// Call the logout handler
	handler := http.HandlerFunc(logoutHandler)
	handler.ServeHTTP(rr, req)

	// Should redirect to index
	if status := rr.Code; status != http.StatusSeeOther {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusSeeOther)
	}

	if loc := rr.Header().Get("Location"); loc != "/" {
		t.Errorf("handler returned wrong redirect location: got %v want %v", loc, "/")
	}

	// Get the session again to test if authenticated is false
	session, _ = store.Get(req, "gallery-session")
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Check that we're no longer authenticated
	session, _ = store.Get(req, "gallery-session")
	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		t.Error("Session still authenticated after logout")
	}

	if hash, ok := session.Values["password_hash"].(string); ok && hash != "" {
		t.Errorf("Session still has password hash after logout: %s", hash)
	}
}

func TestCreateAESCipherEdgeCases(t *testing.T) {
	// Test with short hash
	shortHash := "abc123" // Too short
	block, err := createAESCipher(shortHash)
	if err != nil {
		t.Errorf("createAESCipher failed with short hash: %v", err)
	}
	if block == nil {
		t.Error("createAESCipher returned nil block with short hash")
	}

	// Test with hash that's exactly 32 bytes
	hash32 := hashPassword("password32bytes_________________")
	block, err = createAESCipher(hash32)
	if err != nil {
		t.Errorf("createAESCipher failed with 32-byte hash: %v", err)
	}
	if block == nil {
		t.Error("createAESCipher returned nil block with 32-byte hash")
	}

	// Test with long hash (more than 32 bytes)
	longHash := hashPassword("very_long_password_that_generates_a_very_long_hash_value")
	block, err = createAESCipher(longHash)
	if err != nil {
		t.Errorf("createAESCipher failed with long hash: %v", err)
	}
	if block == nil {
		t.Error("createAESCipher returned nil block with long hash")
	}
}
