package sdk

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestLoadConfigFromString(t *testing.T) {
	toml := `
title = "sdk-test"

[[rules]]
id = "test-rule"
description = "test rule"
regex = '''testsecret_[A-Za-z0-9]{6}'''
keywords = ["testsecret_"]
`

	cfg, err := LoadConfigFromString(toml)
	if err != nil {
		t.Fatalf("LoadConfigFromString() error = %v", err)
	}

	if cfg.Title != "sdk-test" {
		t.Fatalf("expected title sdk-test, got %q", cfg.Title)
	}

	if _, ok := cfg.Rules["test-rule"]; !ok {
		t.Fatalf("expected translated rule test-rule")
	}
}

func TestScannerScanStringDoesNotAccumulateFindings(t *testing.T) {
	scanner := NewScanner(testConfig())

	first, err := scanner.ScanString("value=testsecret_ABC123")
	if err != nil {
		t.Fatalf("ScanString() first call error = %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("expected 1 finding on first call, got %d", len(first))
	}

	second, err := scanner.ScanString("value=testsecret_ABC123")
	if err != nil {
		t.Fatalf("ScanString() second call error = %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("expected 1 finding on second call, got %d", len(second))
	}
}

func TestScannerScanPath(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(target, []byte("value=testsecret_ABC123\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	scanner := NewScanner(testConfig())
	findings, err := scanner.ScanPath(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("ScanPath() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].RuleID != "test-rule" {
		t.Fatalf("expected rule test-rule, got %q", findings[0].RuleID)
	}
}

func TestScannerScanStringWithState_Negative(t *testing.T) {
	scanner := NewScanner(testConfig())

	result, err := scanner.ScanStringWithState("value=testsecret_ABC123", nil)
	if err != nil {
		t.Fatalf("ScanStringWithState() error = %v", err)
	}

	if result.State != VectorStateNegative {
		t.Fatalf("expected %q state, got %q", VectorStateNegative, result.State)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
}

func TestScannerScanStringWithState_PositiveWithRuleExemption(t *testing.T) {
	scanner := NewScanner(testConfig())
	exemptions := NewExemptionManager()
	exemptions.AddRuleID("test-rule")

	result, err := scanner.ScanStringWithState("value=testsecret_ABC123", exemptions)
	if err != nil {
		t.Fatalf("ScanStringWithState() error = %v", err)
	}

	if result.State != VectorStatePositive {
		t.Fatalf("expected %q state, got %q", VectorStatePositive, result.State)
	}
}

func testConfig() config.Config {
	return config.Config{
		Title: "sdk-test",
		Rules: map[string]config.Rule{
			"test-rule": {
				RuleID:      "test-rule",
				Description: "test rule",
				Regex:       regexp.MustCompile(`testsecret_[A-Za-z0-9]{6}`),
				Keywords:    []string{"testsecret_"},
			},
		},
		Keywords: map[string]struct{}{
			"testsecret_": {},
		},
		OrderedRules: []string{"test-rule"},
	}
}
