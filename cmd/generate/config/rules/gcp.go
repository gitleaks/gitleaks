package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

// TODO this one could probably use some work
func GCPServiceAccount() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\"type\": \"service_account\"`),
		Keywords:    []string{`\"type\": \"service_account\"`},
	}

	// validate
	tps := []string{
		`"type": "service_account"`,
	}
	return validate(r, tps)
}
