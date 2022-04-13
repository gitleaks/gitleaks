package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func Beamer() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Beamer API token",
		RuleID:      "beamer-api-token",
		SecretGroup: 1,
		Regex: generateSemiGenericRegex([]string{"beamer"},
			`b_[a-z0-9=_\-]{44}`),
		Keywords: []string{"beamer"},
	}

	// validate
	tps := []string{
		"beamer := \"b_" + sampleAlphaNumeric32Token + "-_=_xxxxxxxx\"",
	}
	return validate(r, tps)
}
