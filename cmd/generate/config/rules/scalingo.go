package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ScalingoAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:      "scalingo-api-token",
		Regex:       utils.GenerateUniqueTokenRegex(`tk-us-[\w-]{48}`, false),
		Entropy:     2,
		Keywords:    []string{"tk-us-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("scalingo", "tk-us-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("48")))
	tps = append(tps,
		`scalingo_api_token = "tk-us-loys7ib9yrxcys_ta2sq85mjar6lgcsspkd9x61s7h5epf_-"`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
