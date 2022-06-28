package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func OktaAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "okta-access-token",
		Description: "Okta Access Token",
		Regex: generateSemiGenericRegex([]string{"okta"},
			alphaNumericExtended("42")),
		SecretGroup: 1,
		Keywords: []string{
			"okta",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("okta", secrets.NewSecret(alphaNumeric("42"))),
	}
	return validate(r, tps, nil)
}
