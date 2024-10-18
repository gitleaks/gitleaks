package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
		RuleID:      "contentful-delivery-api-token",
		Regex: utils.GenerateSemiGenericRegex([]string{"contentful"},
			utils.AlphaNumericExtended("43"), true),
		Keywords: []string{"contentful"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("contentful", secrets.NewSecret(utils.AlphaNumeric("43")))
	return utils.Validate(r, tps, nil)
}
