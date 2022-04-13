package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost API token",
		RuleID:      "easypost-api-token",
		Regex:       regexp.MustCompile(`EZAK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZAK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZAK", "EZAK"+sampleAlphaNumeric54Token),
	}
	return validate(r, tps)
}

func EasyPostTestAPI() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost test API token",
		RuleID:      "easypost-test-api-token",
		Regex:       regexp.MustCompile(`EZTK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZTK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZTK", "EZTK"+sampleAlphaNumeric54Token),
	}
	return validate(r, tps)
}
