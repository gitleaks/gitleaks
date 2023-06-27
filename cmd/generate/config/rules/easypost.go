package rules

import (
	"regexp"

	"github.com/gitleaks/gitleaks/v8/cmd/generate/secrets"
	"github.com/gitleaks/gitleaks/v8/config"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost API token",
		RuleID:      "easypost-api-token",
		Regex:       regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZAK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZAK", "EZAK"+secrets.NewSecret(alphaNumeric("54"))),
	}
	return validate(r, tps, nil)
}

func EasyPostTestAPI() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost test API token",
		RuleID:      "easypost-test-api-token",
		Regex:       regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZTK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZTK", "EZTK"+secrets.NewSecret(alphaNumeric("54"))),
	}
	return validate(r, tps, nil)
}
