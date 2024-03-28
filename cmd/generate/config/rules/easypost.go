package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
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
		Description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
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
