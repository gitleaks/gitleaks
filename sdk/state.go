package sdk

import "github.com/zricethezav/gitleaks/v8/report"

// VectorState models scan-state posture after applying exemptions.
type VectorState string

const (
	VectorStateEmpty    VectorState = "empty"
	VectorStatePositive VectorState = "positive"
	VectorStateNegative VectorState = "negative"
	VectorStateAnti     VectorState = "anti"
)

// ExemptionManager holds finding matchers considered exempt.
type ExemptionManager struct {
	fingerprints map[string]struct{}
	ruleIDs      map[string]struct{}
	paths        map[string]struct{}
}

// NewExemptionManager creates an empty exemption manager.
func NewExemptionManager() *ExemptionManager {
	return &ExemptionManager{
		fingerprints: map[string]struct{}{},
		ruleIDs:      map[string]struct{}{},
		paths:        map[string]struct{}{},
	}
}

// AddFingerprint exempts a finding fingerprint.
func (e *ExemptionManager) AddFingerprint(fingerprint string) {
	if e == nil || fingerprint == "" {
		return
	}
	e.fingerprints[fingerprint] = struct{}{}
}

// AddRuleID exempts all findings produced by a rule.
func (e *ExemptionManager) AddRuleID(ruleID string) {
	if e == nil || ruleID == "" {
		return
	}
	e.ruleIDs[ruleID] = struct{}{}
}

// AddPath exempts all findings from a path.
func (e *ExemptionManager) AddPath(path string) {
	if e == nil || path == "" {
		return
	}
	e.paths[path] = struct{}{}
}

// IsExempt reports whether finding is exempt based on configured matchers.
func (e *ExemptionManager) IsExempt(f report.Finding) bool {
	if e == nil {
		return false
	}
	if _, ok := e.fingerprints[f.Fingerprint]; ok {
		return true
	}
	if _, ok := e.ruleIDs[f.RuleID]; ok {
		return true
	}
	if _, ok := e.paths[f.File]; ok {
		return true
	}
	return false
}

// EvaluateVectorState determines vector state for findings after exemptions.
//
// States:
// - empty: no findings
// - positive: findings exist but all exempt
// - negative: at least one non-exempt finding
// - anti: malformed findings detected (policy-unsafe state)
func EvaluateVectorState(findings []report.Finding, exemptions *ExemptionManager) VectorState {
	if len(findings) == 0 {
		return VectorStateEmpty
	}

	activeCount := 0
	exemptCount := 0

	for _, finding := range findings {
		if finding.RuleID == "" {
			return VectorStateAnti
		}
		if exemptions != nil && exemptions.IsExempt(finding) {
			exemptCount++
			continue
		}
		activeCount++
	}

	if activeCount > 0 {
		return VectorStateNegative
	}
	if exemptCount > 0 {
		return VectorStatePositive
	}

	return VectorStateEmpty
}
