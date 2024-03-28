package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
		RuleID:      "adobe-client-id",
		Regex:       generateSemiGenericRegex([]string{"adobe"}, hex("32"), true),
		Keywords:    []string{"adobe"},
	}

	// validate
	tps := []string{
		generateSampleSecret("adobe", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}

func AdobeClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Adobe Client Secret, which, if exposed, could allow unauthorized Adobe service access and data manipulation.",
		RuleID:      "adobe-client-secret",
		Regex:       generateUniqueTokenRegex(`(p8e-)(?i)[a-z0-9]{32}`, true),
		Keywords:    []string{"p8e-"},
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + secrets.NewSecret(hex("32")) + "\"",
	}
	return validate(r, tps, nil)
}
