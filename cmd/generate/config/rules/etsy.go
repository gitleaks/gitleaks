package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EtsyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "etsy-access-token",
		Description: "Etsy Access Token",
		Regex:       generateSemiGenericRegex([]string{"etsy"}, alphaNumeric("24")),
		SecretGroup: 1,
		Keywords: []string{
			"etsy",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("etsy", secrets.NewSecret(alphaNumeric("24"))),
	}
	return validate(r, tps, nil)
}
