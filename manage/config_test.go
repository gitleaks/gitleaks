package manage

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsValidURL(t *testing.T) {
	testCases := []struct {
		name        string
		rawURL      string
		expectValid bool
	}{
		{
			name:        "Valid URL",
			rawURL:      "https://www.example.com",
			expectValid: true,
		},
		{
			name:        "Invalid URL (missing scheme)",
			rawURL:      "www.example.com",
			expectValid: false,
		},
		{
			name:        "Invalid URL (invalid scheme)",
			rawURL:      "htt://www.example.com",
			expectValid: false,
		},
		{
			name:        "Invalid URL (missing domain)",
			rawURL:      "https://",
			expectValid: false,
		},
		{
			name:        "Invalid URL (empty string)",
			rawURL:      "",
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isValid := isValidURL(tc.rawURL)
			if isValid != tc.expectValid {
				t.Errorf("Expected isValidURL(%q) to be %v, but got %v", tc.rawURL, tc.expectValid, isValid)
			}
		})
	}
}

func TestFetchConfig(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		wantErr    bool
		errStr     string
	}{
		{
			name:       "Successful fetch",
			statusCode: http.StatusOK,
			body:       []byte("test config"),
			wantErr:    false,
		},
		{
			name:       "Empty body",
			statusCode: http.StatusOK,
			body:       nil,
			wantErr:    true,
			errStr:     "empty response body from URL",
		},
		{
			name:       "Bad status code",
			statusCode: http.StatusNotFound,
			body:       nil,
			wantErr:    true,
			errStr:     "status code:404 returned from remote URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write(tt.body)
			}))
			defer ts.Close()

			got, err := fetch(ts.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("fetch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err.Error() != tt.errStr {
				t.Errorf("fetch() error = %v, wantErrStr %v", err, tt.errStr)
				return
			}

			if !tt.wantErr && !bytes.Equal(got, tt.body) {
				t.Errorf("fetch() = %v, want %v", string(got), tt.body)
			}
		})
	}
}

func TestFetchConfigError(t *testing.T) {
	_, err := fetch("invalid://url")
	if err == nil {
		t.Errorf("Expected an error for invalid URL, got nil")
	}
}

func TestFetchConfigBodyReadError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1") // This will cause io.ReadAll to fail
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	_, err := fetch(ts.URL)
	if err == nil {
		t.Errorf("Expected an error for body read failure, got nil")
	}
}
