package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-id",
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adobe"}, utils.Hex("32"), true),
		Entropy:     2,
		Keywords:    []string{"adobe"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adobe", secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}

func AdobeClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adobe-client-secret",
		Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:       utils.GenerateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false),
		Entropy:     2,
		Keywords:    []string{"p8e-"},
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + secrets.NewSecret(utils.Hex("32")) + "\"",
	}
	return utils.Validate(r, tps, nil)
}
