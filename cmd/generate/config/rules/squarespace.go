package rules

import (
	"github.com/gitleaks/gitleaks/v8/cmd/generate/secrets"
	"github.com/gitleaks/gitleaks/v8/config"
)

func SquareSpaceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "squarespace-access-token",
		Description: "Squarespace Access Token",
		Regex:       generateSemiGenericRegex([]string{"squarespace"}, hex8_4_4_4_12()),
		SecretGroup: 1,
		Keywords: []string{
			"squarespace",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("squarespace", secrets.NewSecret(hex8_4_4_4_12())),
	}
	return validate(r, tps, nil)
}
