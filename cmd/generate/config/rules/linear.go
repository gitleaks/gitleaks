package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear API Token",
		RuleID:      "linear-api-key",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", "lin_api_"+sampleAlphaNumeric40Token),
	}
	return validate(r, tps)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear Client Secret",
		RuleID:      "linear-client-secret",
		Regex:       generateSemiGenericRegex([]string{"linear"}, hex32),
		Keywords:    []string{"linear"},
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", sampleHex32Token),
	}
	return validate(r, tps)
}
