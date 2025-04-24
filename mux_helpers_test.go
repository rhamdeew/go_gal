package main

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

// SetURLVars sets URL variables for a request to be used by the mux.Router
func SetURLVars(r *http.Request, vars map[string]string) *http.Request {
	return mux.SetURLVars(r, vars)
}

// Helper function for older versions of Gorilla Mux that don't have SetURLVars
// If mux doesn't have SetURLVars function, you can use this instead
type contextKey int

const (
	varsKey contextKey = iota
)

// SetURLVarsAlternate sets URL variables in the request context for a request
// Use this if the mux package doesn't have SetURLVars function
func SetURLVarsAlternate(r *http.Request, vars map[string]string) *http.Request {
	ctx := context.WithValue(r.Context(), varsKey, vars)
	return r.WithContext(ctx)
}