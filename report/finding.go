package report

import (
	"encoding/json"
	"math"
	"strings"
)

// VerificationStatus explicitly differentiates between findings that don't support verification,
// and the potential outcomes of verification.
type VerificationStatus int

// TODO: Review these names as there may be better/clearer options.
const (
	// NotSupported indicates that the finding cannot be verified.
	NotSupported VerificationStatus = iota
	// Error indicates that an error occurred.
	Error
	// Skipped indicates that verification wasn't attempted, for some reason.
	Skipped
	// ConfirmedInvalid indicates that the secret did not match the expected status and body.
	ConfirmedInvalid
	// ConfirmedValid indicates that the secret matched the expected status and body.
	ConfirmedValid
)

func (v VerificationStatus) String() string {
	return [...]string{
		"NotSupported",
		"Error",
		"Skipped",
		"ConfirmedInvalid",
		"ConfirmedValid",
	}[v]
}

func (v VerificationStatus) MarshalJSON() ([]byte, error) {
	// If a finding doesn't support verification, use an empty string
	// to be consistent with how other fields work.
	if v == NotSupported {
		return json.Marshal("")
	}
	return json.Marshal(v.String())
}

// Finding contains information about strings that
// have been captured by a tree-sitter query.
type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Secret contains the full content of what is matched in
	// the tree-sitter query.
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// TODO: Ensure this serializes properly
	Status       VerificationStatus
	StatusReason string
	Attributes   map[string]string `json:"-"`
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.Replace(f.Line, f.Secret, secret, -1)
	f.Match = strings.Replace(f.Match, f.Secret, secret, -1)
	f.Secret = secret
}

func maskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	len := float64(len(secret))
	if len <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(len * prc / float64(100)))

	return secret[:lth] + "..."
}
