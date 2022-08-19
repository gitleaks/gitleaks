package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ReadMe() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "readme-api-token",
		Description: "Readme API token",
		Regex:       generateUniqueTokenRegex(`rdme_[a-z0-9]{70}`),
		SecretGroup: 1,
		Keywords: []string{
			"rdme_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("api-token", "rdme_"+secrets.NewSecret(alphaNumeric("70"))),
	}
	return validate(r, tps, nil)
}
