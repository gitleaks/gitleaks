package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Prefect() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "prefect-api-token",
		Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
		Regex:       utils.GenerateUniqueTokenRegex(`pnu_[a-zA-Z0-9]{36}`, false),
		Entropy:     2,
		Keywords: []string{
			"pnu_",
		},
	}

	// validate
	r.TPs = utils.GenerateSampleSecrets("api-token", "pnu_"+secrets.NewSecret(utils.AlphaNumeric("36")))
	r.FPs = []string{
		`PREFECT_API_KEY = "pnu_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"`,
	}
	return &r
}
