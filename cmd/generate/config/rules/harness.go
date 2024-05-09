package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HarnessPAT() *config.Rule {
	// Define rule for Harness Personal Access Token (PAT)
	r := config.Rule{
		Description: "Identified a Harness Personal Access Token (PAT), risking unauthorized access to a Harness account.",
		RuleID:      "harness-pat",
		Regex:       regexp.MustCompile(`pat\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{24}`),
		Keywords:    []string{"pat."},
	}

	// Generate a sample secret for validation
	tps := []string{
		generateSampleSecret("harness", "pat."+secrets.NewSecret(alphaNumeric("24"))+"."+secrets.NewSecret(alphaNumeric("24"))+"."+secrets.NewSecret(alphaNumeric("24"))),
	}

	// Validate the rule
	return validate(r, tps, nil)
}
