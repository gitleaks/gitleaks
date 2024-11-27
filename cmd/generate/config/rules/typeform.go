package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Typeform() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "typeform-api-token",
		Description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
		Regex: utils.GenerateSemiGenericRegex([]string{"typeform"},
			`tfp_[a-z0-9\-_\.=]{59}`, true),
		Keywords: []string{
			"tfp_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("typeformAPIToken", "tfp_"+secrets.NewSecret(utils.AlphaNumericExtended("59")))
	return utils.Validate(r, tps, nil)
}
