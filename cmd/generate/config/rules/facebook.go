package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Facebook() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:      "facebook",
		Regex:       generateSemiGenericRegex([]string{"facebook"}, hex("32"), true),

		Keywords: []string{"facebook"},
	}

	// validate
	tps := []string{
		generateSampleSecret("facebook", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
