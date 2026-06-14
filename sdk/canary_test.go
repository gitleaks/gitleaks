package sdk

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
)

func TestAddCanaryRule_DefaultPrefixes(t *testing.T) {
	cfg := config.Config{}

	if err := AddCanaryRule(&cfg); err != nil {
		t.Fatalf("AddCanaryRule() error = %v", err)
	}

	rule, ok := cfg.Rules[canaryRuleID]
	if !ok {
		t.Fatalf("expected canary rule %q", canaryRuleID)
	}

	if rule.Regex == nil {
		t.Fatalf("expected canary regex to be set")
	}

	if _, ok := cfg.Keywords["org_canary"]; !ok {
		t.Fatalf("expected org_canary keyword")
	}
}

func TestAddCanaryRule_CustomPrefixesDetect(t *testing.T) {
	cfg := config.Config{}
	if err := AddCanaryRule(&cfg, "teamtrap"); err != nil {
		t.Fatalf("AddCanaryRule() error = %v", err)
	}

	scanner := NewScanner(cfg)
	findings, err := scanner.ScanString("value=teamtrap_abcdef123456789")
	if err != nil {
		t.Fatalf("ScanString() error = %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 canary finding, got %d", len(findings))
	}

	if findings[0].RuleID != canaryRuleID {
		t.Fatalf("expected rule %q, got %q", canaryRuleID, findings[0].RuleID)
	}
}

func TestAddCanaryRule_RejectsEmptyPrefixes(t *testing.T) {
	cfg := config.Config{}

	err := AddCanaryRule(&cfg, "", " ")
	if err == nil {
		t.Fatalf("expected error for empty prefixes")
	}
}
