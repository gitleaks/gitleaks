package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LinkedinClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-secret",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, utils.AlphaNumeric("16"), true),

		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("linkedin", secrets.NewSecret(utils.AlphaNumeric("16"))),
	}
	return utils.Validate(r, tps, nil)
}

func LinkedinClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "linkedin-client-id",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		Regex: utils.GenerateSemiGenericRegex([]string{
			"linkedin",
			"linked-in",
		}, utils.AlphaNumeric("14"), true),

		Keywords: []string{
			"linkedin",
			"linked-in",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("linkedin", secrets.NewSecret(utils.AlphaNumeric("14"))),
	}
	return utils.Validate(r, tps, nil)
}
