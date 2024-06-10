package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case: correct auth header
	{
		headers := http.Header{}
		headers.Add("Authorization", "ApiKey my-secret-key")

		apiKey, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if apiKey != "my-secret-key" {
			t.Fatalf("expected 'my-secret-key', got %v", apiKey)
		}
	}

	// Test case: missing auth header
	{
		headers := http.Header{}

		_, err := GetAPIKey(headers)
		if err == nil || !errors.Is(err, ErrNoAuthHeaderIncluded) {
			t.Fatalf("expected error 'ErrNoAuthHeaderIncluded', got %v", err)
		}
	}

	// Test case: malformed header
	{
		headers := http.Header{}
		headers.Add("Authorization", "Bearer token")

		_, err := GetAPIKey(headers)
		if err == nil || err.Error() != "malformed authorization header" {
			t.Fatalf("expected error 'malformed authorization header', got %v", err)
		}
	}
}
