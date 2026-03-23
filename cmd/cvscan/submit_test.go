package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSubmit_ReadsJSONAndSubmits(t *testing.T) {
	var received submitRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/submit-findings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok_test" {
			t.Errorf("unexpected Authorization header: %s", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	originalURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalURL }()

	// Write a sidecar JSON file
	tmpDir := t.TempDir()
	sidecar := filepath.Join(tmpDir, ".cvscan-results.json")
	result := &ScanResult{
		ReposPath: "/tmp/repos",
		Findings: []Finding{
			{
				ScanType:       ScanTypeSecrets,
				RuleID:         "aws-access-key",
				SecretRedacted: "AKIA********MPLE",
				File:           "config.py",
				StartLine:      10,
			},
		},
		Summary: Summary{TotalFindings: 1, SecretsFindings: 1},
	}
	if err := writeResultsJSON(result, sidecar); err != nil {
		t.Fatal(err)
	}

	err := runSubmit(nil, "eng_test123", "tok_test", sidecar)
	if err != nil {
		t.Fatal(err)
	}

	if received.ID != "eng_test123" {
		t.Errorf("expected ID eng_test123, got %s", received.ID)
	}
	if received.Summary.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", received.Summary.TotalFindings)
	}
}

func TestRunSubmit_FileNotFound(t *testing.T) {
	err := runSubmit(nil, "eng_test123", "/nonexistent/path/results.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSubmitFindings_Success(t *testing.T) {
	var received submitRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/submit-findings" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok_abc123" {
			t.Errorf("unexpected Authorization header: %s", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result := &ScanResult{
		ReposPath: "/tmp/repos",
		Findings: []Finding{
			{
				ScanType:       ScanTypeSecrets,
				RuleID:         "aws-access-key",
				SecretRedacted: "AKIA********MPLE",
				File:           "config.py",
				StartLine:      10,
			},
		},
		Summary: Summary{TotalFindings: 1, SecretsFindings: 1},
	}

	err := submitFindings(server.URL, "eng_abc123", "tok_abc123", result)
	if err != nil {
		t.Fatal(err)
	}

	if received.ID != "eng_abc123" {
		t.Errorf("expected ID eng_abc123, got %s", received.ID)
	}
	if received.Summary.TotalFindings != 1 {
		t.Errorf("expected 1 finding, got %d", received.Summary.TotalFindings)
	}

	for _, f := range received.Findings {
		if f.SecretRedacted == "AKIAIOSFODNN7EXAMPLE" {
			t.Error("raw secret was sent — redaction failed")
		}
	}
}

func TestSubmitFindings_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	result := &ScanResult{Summary: Summary{}}
	err := submitFindings(server.URL, "eng_abc123", "tok_abc123", result)
	if err == nil {
		t.Error("expected error on server error")
	}
}

func TestSubmitFindings_Conflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()

	result := &ScanResult{Summary: Summary{}}
	err := submitFindings(server.URL, "eng_abc123", "tok_abc123", result)
	if err == nil {
		t.Error("expected error on 409 conflict")
	}
	if err.Error() != "findings already submitted for this ID" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestValidateID(t *testing.T) {
	tests := []struct {
		id      string
		wantErr bool
	}{
		{"eng_abc123", false},
		{"tok_xyz789", true},
		{"ENG-123", true},
		{"invalid", true},
		{"", true},
	}

	for _, tt := range tests {
		err := ValidateID(tt.id)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateID(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
		}
	}
}

func TestWriteResultsJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "results.json")

	result := &ScanResult{
		ReposPath: "/tmp/repos",
		Summary:   Summary{TotalFindings: 5},
	}
	if err := writeResultsJSON(result, path); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var loaded ScanResult
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Summary.TotalFindings != 5 {
		t.Errorf("expected 5 findings, got %d", loaded.Summary.TotalFindings)
	}
}

func TestJsonSidecarPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cvscan-report.html", ".cvscan-results.json"},
		{"output/report.html", filepath.Join("output", ".cvscan-results.json")},
		{"", ".cvscan-results.json"},
	}

	for _, tt := range tests {
		got := jsonSidecarPath(tt.input)
		if got != tt.want {
			t.Errorf("jsonSidecarPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
