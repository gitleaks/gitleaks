package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EtsyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "etsy-access-token",
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		Regex:       generateSemiGenericRegex([]string{"etsy"}, alphaNumeric("24"), true),

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
