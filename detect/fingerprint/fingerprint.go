package fingerprint

import "github.com/zricethezav/gitleaks/v8/report"

// Fingerprint is necessary to simultaneously support 'old' and 'new' logic.
type Fingerprint interface {
	GetFingerprint(f report.Finding) string
	IsIgnored(f report.Finding) bool
}
