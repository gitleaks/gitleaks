package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Beamer() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
		RuleID:      "beamer-api-token",
		Regex: generateSemiGenericRegex([]string{"beamer"},
			`b_[a-z0-9=_\-]{44}`, true),
		Keywords: []string{"beamer"},
	}

	// validate
	tps := []string{
		generateSampleSecret("beamer", "b_"+secrets.NewSecret(alphaNumericExtended("44"))),
	}
	return validate(r, tps, nil)
}
