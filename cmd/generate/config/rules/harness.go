package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HarnessApiKey() *config.Rule {
	// Define rule for Harness Personal Access Token (PAT) and Service Account Token (SAT)
	r := config.Rule{
		Description: "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
		RuleID:      "harness-api-key",
		Regex:       regexp.MustCompile(`((?:pat|sat)\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20})`),
		Keywords:    []string{"pat.", "sat."},
	}

	// Generate a sample secret for validation
	tps := []string{
		generateSampleSecret("harness", "pat."+secrets.NewSecret(alphaNumeric("22"))+"."+secrets.NewSecret(alphaNumeric("24"))+"."+secrets.NewSecret(alphaNumeric("20"))),
		generateSampleSecret("harness", "sat."+secrets.NewSecret(alphaNumeric("22"))+"."+secrets.NewSecret(alphaNumeric("24"))+"."+secrets.NewSecret(alphaNumeric("20"))),
	}

	// Validate the rule
	return validate(r, tps, nil)
}
