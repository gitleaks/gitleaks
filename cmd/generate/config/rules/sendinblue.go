package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       utils.GenerateUniqueTokenRegex(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`, false),
		Entropy:     2,
		Keywords: []string{
			"xkeysib-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sendinblue", "xkeysib-"+secrets.NewSecret(utils.Hex("64"))+"-"+secrets.NewSecret(utils.AlphaNumeric("16")))
	return utils.Validate(r, tps, nil)
}
