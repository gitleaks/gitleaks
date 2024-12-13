package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SettlemintPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Personal Access Token.",
		RuleID:      "settlemint-personal-access-token",
		Regex:       utils.GenerateUniqueTokenRegex(`sm_pat_[a-zA-Z0-9]{16}`, false),
		Entropy:     3,
		Keywords: []string{
			"sm_pat",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("settlemintToken", "sm_pat_"+secrets.NewSecret(utils.AlphaNumeric("16")))
	fps := []string{
		"nonMatchingToken := \"" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\"",
		"nonMatchingToken := \"sm_pat_" + secrets.NewSecret(utils.AlphaNumeric("10")) + "\"",
	}
	return utils.Validate(r, tps, fps)
}

func SettlemintApplicationAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Application Access Token.",
		RuleID:      "settlemint-application-access-token",
		Regex:       utils.GenerateUniqueTokenRegex(`sm_aat_[a-zA-Z0-9]{16}`, false),
		Entropy:     3,
		Keywords: []string{
			"sm_aat",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("settlemintToken", "sm_aat_"+secrets.NewSecret(utils.AlphaNumeric("16")))
	fps := []string{
		"nonMatchingToken := \"" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\"",
		"nonMatchingToken := \"sm_aat_" + secrets.NewSecret(utils.AlphaNumeric("10")) + "\"",
	}
	return utils.Validate(r, tps, fps)
}

func SettlemintServiceAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Settlemint Service Access Token.",
		RuleID:      "settlemint-service-access-token",
		Regex:       utils.GenerateUniqueTokenRegex(`sm_sat_[a-zA-Z0-9]{16}`, false),
		Entropy:     3,
		Keywords: []string{
			"sm_sat",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("settlemintToken", "sm_sat_"+secrets.NewSecret(utils.AlphaNumeric("16")))
	fps := []string{
		"nonMatchingToken := \"" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\"",
		"nonMatchingToken := \"sm_sat_" + secrets.NewSecret(utils.AlphaNumeric("10")) + "\"",
	}
	return utils.Validate(r, tps, fps)
}
