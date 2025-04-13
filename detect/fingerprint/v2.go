package fingerprint

import (
	"crypto/sha1"
	"fmt"

	"github.com/zricethezav/gitleaks/v8/report"
)

var _ Fingerprint = (*V2)(nil)

// V2 is a new .gitleaksignore format using the hash of the secret.
type V2 struct {
	gitleaksIgnore map[string]struct{}
}

func NewV2(gitleaksIgnore map[string]struct{}) Fingerprint {
	return &V2{
		gitleaksIgnore: gitleaksIgnore,
	}
}

// GetFingerprint returns the hash of the secret, prefixed by the algorithm (sha1_).
func (*V2) GetFingerprint(f report.Finding) string {
	h := sha1.New()
	h.Write([]byte(f.Secret))
	hash := h.Sum(nil)

	return fmt.Sprintf("sha1_%x", hash)
}
func (v *V2) IsIgnored(f report.Finding) bool {
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
