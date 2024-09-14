package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PrivateKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		RuleID:      "private-key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*KEY( BLOCK)?----`),
		Keywords:    []string{"-----BEGIN"},
	}

	// validate
	tps := []string{`-----BEGIN PRIVATE KEY-----
anything
-----END PRIVATE KEY-----`,
		`-----BEGIN RSA PRIVATE KEY-----
abcdefghijklmnopqrstuvwxyz
-----END RSA PRIVATE KEY-----
`,
		`-----BEGIN PRIVATE KEY BLOCK-----
anything
-----END PRIVATE KEY BLOCK-----`,
	} // gitleaks:allow
	return validate(r, tps, nil)
}
