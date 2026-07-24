package sdk

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestEvaluateVectorState_Empty(t *testing.T) {
	state := EvaluateVectorState(nil, nil)
	if state != VectorStateEmpty {
		t.Fatalf("expected %q, got %q", VectorStateEmpty, state)
	}
}

func TestEvaluateVectorState_Negative(t *testing.T) {
	findings := []report.Finding{{RuleID: canaryRuleID, File: "a.txt", Fingerprint: "fp1"}}
	state := EvaluateVectorState(findings, nil)
	if state != VectorStateNegative {
		t.Fatalf("expected %q, got %q", VectorStateNegative, state)
	}
}

func TestEvaluateVectorState_PositiveWhenExempt(t *testing.T) {
	findings := []report.Finding{{RuleID: canaryRuleID, File: "a.txt", Fingerprint: "fp1"}}
	exemptions := NewExemptionManager()
	exemptions.AddFingerprint("fp1")

	state := EvaluateVectorState(findings, exemptions)
	if state != VectorStatePositive {
		t.Fatalf("expected %q, got %q", VectorStatePositive, state)
	}
}

func TestEvaluateVectorState_AntiMalformedFinding(t *testing.T) {
	findings := []report.Finding{{RuleID: "", File: "a.txt", Fingerprint: "fp1"}}
	state := EvaluateVectorState(findings, nil)
	if state != VectorStateAnti {
		t.Fatalf("expected %q, got %q", VectorStateAnti, state)
	}
}

func TestExemptionManager_RuleAndPath(t *testing.T) {
	exemptions := NewExemptionManager()
	exemptions.AddRuleID(canaryRuleID)
	exemptions.AddPath("b.txt")

	if !exemptions.IsExempt(report.Finding{RuleID: canaryRuleID, File: "a.txt"}) {
		t.Fatalf("expected rule exemption to match")
	}

	if !exemptions.IsExempt(report.Finding{RuleID: "other", File: "b.txt"}) {
		t.Fatalf("expected path exemption to match")
	}

	if exemptions.IsExempt(report.Finding{RuleID: "other", File: "c.txt"}) {
		t.Fatalf("unexpected exemption match")
	}
}
