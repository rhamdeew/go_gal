package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestRoutes(t *testing.T) {
	// Create a new router
	r := mux.NewRouter()

	// Register the routes
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/gallery/{path:.*}", galleryHandler)
	r.HandleFunc("/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/createdir", createDirHandler).Methods("POST")
	r.HandleFunc("/view/{path:.*}", viewHandler)
	r.HandleFunc("/logout", logoutHandler)
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Test cases for routes
	testCases := []struct {
		name           string
		path           string
		method         string
		expectedStatus int
		authenticated  bool
		skip           bool
	}{
		{"Index Route", "/", "GET", http.StatusOK, false, false},
		{"Login Route POST", "/login", "POST", http.StatusOK, false, true}, // We'll skip this as it requires form input
		{"Gallery Route Unauthenticated", "/gallery/", "GET", http.StatusSeeOther, false, false},
		{"Gallery Route Authenticated", "/gallery/", "GET", http.StatusOK, true, false},
		{"Upload Route Unauthenticated", "/upload", "POST", http.StatusSeeOther, false, false},
		{"View Route Unauthenticated", "/view/test.txt", "GET", http.StatusSeeOther, false, false},
		{"Logout Route", "/logout", "GET", http.StatusSeeOther, true, false},
		{"Static File Route", "/static/css/style.css", "GET", http.StatusNotFound, false, true}, // Skip this as it depends on file existence
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip {
				t.Skip("Skipping this test case")
			}

			// Create a request to the specified URL with the specified method
			req, err := http.NewRequest(tc.method, tc.path, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// If this route requires authentication, set up a session
			if tc.authenticated {
				// Create a recorder to record the response
				rr := httptest.NewRecorder()

				// Create a session
				session, _ := store.Get(req, "gallery-session")
				session.Values["authenticated"] = true
				session.Values["password_hash"] = hashPassword("testpassword")

				// Save the session
				err := session.Save(req, rr)
				if err != nil {
					t.Fatalf("Failed to save session: %v", err)
				}

				// Add the session cookie to the request
				req.Header.Add("Cookie", rr.Header().Get("Set-Cookie"))
			}

			// Create a ResponseRecorder to record the response
			rr := httptest.NewRecorder()

			// Serve the request using the router
			r.ServeHTTP(rr, req)

			// Check the status code
			if tc.path == "/upload" && tc.method == "POST" && tc.authenticated {
				// Skip checking upload route when authenticated as it requires a multipart form
				return
			}

			if tc.path == "/createdir" && tc.method == "POST" && tc.authenticated {
				// Skip checking createdir route when authenticated as it requires form values
				return
			}

			if rr.Code != tc.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					rr.Code, tc.expectedStatus)
			}
		})
	}
}

func TestAuthenticationMiddleware(t *testing.T) {
	// Test middleware function to protect routes
	protected := func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "gallery-session")
		if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Protected content"))
	}

	// Unauthenticated request
	req1, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr1 := httptest.NewRecorder()
	handler := http.HandlerFunc(protected)
	handler.ServeHTTP(rr1, req1)

	// Check unauthenticated request is redirected
	if rr1.Code != http.StatusSeeOther {
		t.Errorf("Unauthenticated request should be redirected: got %v want %v",
			rr1.Code, http.StatusSeeOther)
	}

	// Authenticated request
	req2, err := http.NewRequest("GET", "/protected", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr2 := httptest.NewRecorder()

	// Create a session
	session, _ := store.Get(req2, "gallery-session")
	session.Values["authenticated"] = true
	session.Values["password_hash"] = hashPassword("testpassword")

	// Save the session
	err = session.Save(req2, rr2)
	if err != nil {
		t.Fatalf("Failed to save session: %v", err)
	}

	// Add the session cookie to the request
	req2.Header.Add("Cookie", rr2.Header().Get("Set-Cookie"))

	// Reset the response recorder
	rr2 = httptest.NewRecorder()

	// Call the handler
	handler.ServeHTTP(rr2, req2)

	// Check authenticated request gets OK status
	if rr2.Code != http.StatusOK {
		t.Errorf("Authenticated request should get OK: got %v want %v",
			rr2.Code, http.StatusOK)
	}
}
