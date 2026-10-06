package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHelloHandler(t *testing.T) {
	response := httptest.NewRecorder()
	helloHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://hello.example.com/", nil))
	if response.Code != http.StatusOK || response.Body.String() != "Hello, world!\n" || response.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected response: %d %q %v", response.Code, response.Body.String(), response.Header())
	}
}
