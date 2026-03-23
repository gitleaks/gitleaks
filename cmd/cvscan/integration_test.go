package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// seedRepo creates a temporary directory containing a fake repo with a known
// AWS key so the secrets scanner has something to find.
func seedRepo(t *testing.T) (tmpDir, reportPath string) {
	t.Helper()

	tmpDir = t.TempDir()
	repoDir := filepath.Join(tmpDir, "test-repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatalf("failed to create repo dir: %v", err)
	}

	secretFile := filepath.Join(repoDir, "config.py")
	if err := os.WriteFile(secretFile, []byte(`AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"`), 0o644); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	reportPath = filepath.Join(tmpDir, "report.html")
	return tmpDir, reportPath
}

// TestIntegration_LocalOnly verifies the primary use case: scanning without
// any submission. No mock server is needed because no network calls should
// happen when --id is omitted.
func TestIntegration_LocalOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir, reportPath := seedRepo(t)

	err := runCLI(context.Background(), CLIConfig{
		ReposPath: tmpDir,
		Output:    reportPath,
		Scanners:  "secrets",
	})
	if err != nil {
		t.Fatalf("CLI flow failed: %v", err)
	}

	// HTML report was generated and is non-empty.
	info, err := os.Stat(reportPath)
	if os.IsNotExist(err) {
		t.Fatal("HTML report was not generated")
	} else if err != nil {
		t.Fatalf("failed to stat report: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("HTML report is empty")
	}

	// JSON sidecar was generated.
	jsonPath := jsonSidecarPath(reportPath)
	info, err = os.Stat(jsonPath)
	if os.IsNotExist(err) {
		t.Fatal("JSON sidecar was not generated")
	} else if err != nil {
		t.Fatalf("failed to stat JSON sidecar: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("JSON sidecar is empty")
	}

	t.Log("local-only scan completed successfully, no network calls made")
}

// TestIntegration_WithSubmission verifies scanning + submission via --id.
// A mock server captures the POST /submit-findings payload so we can assert on it.
func TestIntegration_WithSubmission(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Set up mock API server that captures the submission payload.
	var receivedPayload submitRequest
	var submitCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/submit-findings":
			if r.Method != http.MethodPost {
				t.Errorf("expected POST /submit-findings, got %s", r.Method)
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			submitCalled = true
			if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
				t.Errorf("failed to decode submit body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Override apiBaseURL for the test.
	originalURL := apiBaseURL
	apiBaseURL = server.URL
	defer func() { apiBaseURL = originalURL }()

	tmpDir, reportPath := seedRepo(t)

	err := runCLI(context.Background(), CLIConfig{
		ID:        "eng_test123",
		Token:     "tok_test123",
		ReposPath: tmpDir,
		Output:    reportPath,
		Scanners:  "secrets",
	})
	if err != nil {
		t.Fatalf("CLI flow failed: %v", err)
	}

	// Submit endpoint was called.
	if !submitCalled {
		t.Fatal("submit endpoint was never called")
	}

	// ID field matches (not EngagementID).
	if receivedPayload.ID != "eng_test123" {
		t.Errorf("wrong ID in submission: got %q, want %q",
			receivedPayload.ID, "eng_test123")
	}

	// No raw secrets leaked in findings.
	for _, f := range receivedPayload.Findings {
		if f.SecretRedacted == "AKIAIOSFODNN7EXAMPLE" {
			t.Error("raw secret leaked in submission payload")
		}
	}

	// HTML report was generated and is non-empty.
	info, err := os.Stat(reportPath)
	if os.IsNotExist(err) {
		t.Fatal("HTML report was not generated")
	} else if err != nil {
		t.Fatalf("failed to stat report: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("HTML report is empty")
	}

	// JSON sidecar was generated.
	jsonPath := jsonSidecarPath(reportPath)
	if _, err := os.Stat(jsonPath); os.IsNotExist(err) {
		t.Fatal("JSON sidecar was not generated")
	}

	t.Logf("Findings submitted: %d (secrets=%d, iac=%d, repos=%d)",
		receivedPayload.Summary.TotalFindings,
		receivedPayload.Summary.SecretsFindings,
		receivedPayload.Summary.IaCFindings,
		receivedPayload.Summary.ReposScanned,
	)
}
