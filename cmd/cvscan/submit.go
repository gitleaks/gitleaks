package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type submitRequest struct {
	Schema      string    `json:"schema"`
	ID          string    `json:"engagement_id"`
	GeneratedAt string    `json:"generated_at"`
	ReposPath   string    `json:"repos_path"`
	Summary     Summary   `json:"summary"`
	Findings    []Finding `json:"findings"`
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func submitFindings(baseURL, engagementID, token string, result *ScanResult) error {
	payload := submitRequest{
		Schema:      "cloudvisor.cvscan-report.v1",
		ID:          engagementID,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ReposPath:   result.ReposPath,
		Summary:     result.Summary,
		Findings:    result.Findings,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/submit-findings", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach Cloudvisor API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("findings already submitted for this ID")
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
			if msg, ok := body["error"].(string); ok {
				return fmt.Errorf("submission failed with HTTP %d: %s", resp.StatusCode, msg)
			}
		}
		return fmt.Errorf("submission failed with HTTP %d", resp.StatusCode)
	}

	return nil
}

func runSubmit(_ context.Context, engagementID, token, filePath string) error {
	if err := ValidateID(engagementID); err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("--token is required for submission")
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read results file: %w", err)
	}

	var result ScanResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("failed to parse results JSON: %w", err)
	}

	fmt.Print("Submitting findings to Cloudvisor... ")
	if err := submitFindings(apiBaseURL, engagementID, token, &result); err != nil {
		fmt.Println("FAILED")
		return err
	}
	fmt.Println("Done")
	return nil
}

func writeResultsJSON(result *ScanResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func jsonSidecarPath(htmlPath string) string {
	if htmlPath == "" {
		return ".cvscan-results.json"
	}
	dir := filepath.Dir(htmlPath)
	return filepath.Join(dir, ".cvscan-results.json")
}

// ValidateID checks that the engagement ID has the eng_ prefix.
func ValidateID(id string) error {
	if strings.HasPrefix(id, "eng_") {
		return nil
	}
	return fmt.Errorf("invalid engagement ID %q: must start with eng_", id)
}
