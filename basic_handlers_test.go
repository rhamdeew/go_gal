package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Helper function to create authenticated session
func createAuthenticatedSession(t *testing.T, req *http.Request, password string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	session, _ := store.Get(req, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword(password)
	err := session.Save(req, rr)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}
	return rr
}

func TestIndexHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		authenticated    bool
		expectedStatus   int
		expectedLocation string
	}{
		{
			name:           "not authenticated",
			authenticated:  false,
			expectedStatus: http.StatusOK,
		},
		{
			name:             "authenticated",
			authenticated:    true,
			expectedStatus:   http.StatusSeeOther,
			expectedLocation: "/gallery/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(indexHandler)

			if tt.authenticated {
				// Create authenticated session
				sessionRR := createAuthenticatedSession(t, req, "testpassword")
				req.Header.Add("Cookie", sessionRR.Header().Get("Set-Cookie"))
			}

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedLocation != "" {
				if location := rr.Header().Get("Location"); location != tt.expectedLocation {
					t.Errorf("Expected redirect to %s, got %s", tt.expectedLocation, location)
				}
			}
		})
	}
}

func TestLogoutHandler(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
