package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFetchRemoteConfig(t *testing.T) {
	tests := []struct {
		name        string
		handler     http.HandlerFunc
		expectError string
		expectBody  string
	}{
		{
			name: "success",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`title = "test config"`))
			},
			expectBody: `title = "test config"`,
		},
		{
			name: "non-200 status is an error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectError: "unexpected status",
		},
		{
			name: "oversized response is rejected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(make([]byte, int(maxRemoteConfigBytes)+1024))
			},
			expectError: "exceeds max allowed size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			body, err := fetchRemoteConfig(srv.URL)

			if tt.expectError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expectBody, string(body))
		})
	}
}

func TestFetchRemoteConfigUnreachable(t *testing.T) {
	// A closed connection should surface as a request error, not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := fetchRemoteConfig(url)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "unable to fetch remote config"))
}
