package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendGridAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendgrid-api-token",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false),
		Entropy:     2,
		Keywords: []string{
			"SG.",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sengridAPIToken", "SG."+secrets.NewSecret(utils.AlphaNumericExtended("66")))
	return utils.Validate(r, tps, nil)
}
