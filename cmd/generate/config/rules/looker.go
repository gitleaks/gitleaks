package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LookerClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-id",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("20"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecret(utils.AlphaNumeric("20")))
	return utils.Validate(r, tps, nil)
}

func LookerClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
		RuleID:      "looker-client-secret",
		Regex:       utils.GenerateSemiGenericRegex([]string{"looker"}, utils.AlphaNumeric("24"), true),
		Keywords:    []string{"looker"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("looker", secrets.NewSecret(utils.AlphaNumeric("24")))
	return utils.Validate(r, tps, nil)
}
