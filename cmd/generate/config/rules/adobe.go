package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Adobe Client ID (OAuth Web)",
		RuleID:      "adobe-client-id",
		Regex:       generateSemiGenericRegex([]string{"adobe"}, hex("32")),
		SecretGroup: 1,
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
		Description: "Adobe Client Secret",
		RuleID:      "adobe-client-secret",
		Regex:       generateUniqueTokenRegex(`(p8e-)(?i)[a-z0-9]{32}`),
		Keywords:    []string{"p8e-"},
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + secrets.NewSecret(hex("32")) + "\"",
	}
	return validate(r, tps, nil)
}
