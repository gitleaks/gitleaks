package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EtsyAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "etsy-access-token",
		Description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"etsy"}, utils.AlphaNumeric("24"), true),

		Keywords: []string{
			"etsy",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("etsy", secrets.NewSecret(utils.AlphaNumeric("24"))),
	}
	return utils.Validate(r, tps, nil)
}
