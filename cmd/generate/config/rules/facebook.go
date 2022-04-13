package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Facebook() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "facebook",
		RuleID:      "facebook",
		Regex: generateSemiGenericRegex([]string{"facebook"},
			hex32),
		SecretGroup: 1,
		Keywords:    []string{"facebook"},
	}

	// validate
	tps := []string{"facebookToken := \"" + sampleHex32Token + "\""}
	return validate(r, tps)
}
