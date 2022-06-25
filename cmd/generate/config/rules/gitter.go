package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitterAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gitter-access-token",
		Description: "Gitter Access Token",
		Regex: generateSemiGenericRegex([]string{"gitter"},
			alphaNumericExtendedShort("40")),
		SecretGroup: 1,
		Keywords: []string{
			"gitter",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gitter",
			secrets.NewSecret(alphaNumericExtendedShort("40"))),
	}
	return validate(r, tps, nil)
}
