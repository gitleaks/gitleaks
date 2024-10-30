package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CodecovAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "codecov-access-token",
		Description: "Found a pattern resembling a Codecov Access Token, posing a risk of unauthorized access to code coverage reports and sensitive data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"codecov"}, utils.AlphaNumeric("32"), true),
		Keywords: []string{
			"codecov",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("codecov", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
