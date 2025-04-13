package fingerprint

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/report"
)

var _ Fingerprint = (*V1)(nil)

// V1 is the original .gitleaksignore format: `commit:file:rule-id:start-line`.
type V1 struct {
	gitleaksIgnore map[string]struct{}
}

func NewV1(gitleaksIgnore map[string]struct{}) Fingerprint {
	return &V1{
		gitleaksIgnore,
	}
}

func (*V1) GetFingerprint(f report.Finding) string {
	if f.Commit != "" {
		return fmt.Sprintf("%s:%s:%s:%d", f.Commit, f.File, f.RuleID, f.StartLine)
	} else {
		return fmt.Sprintf("%s:%s:%d", f.File, f.RuleID, f.StartLine)
	}
}
func (v *V1) IsIgnored(f report.Finding) bool {
	// check if we should ignore this finding
	if _, ok := v.gitleaksIgnore[f.Fingerprint]; ok {
		return true
	} else if f.Commit != "" {
		// Awkward nested if because I'm not sure how to chain these two conditions.
		if _, ok := v.gitleaksIgnore[f.Fingerprint]; ok {
			return true
		}
	}
	return false
}
