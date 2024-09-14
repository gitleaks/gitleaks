package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SendInBlueAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sendinblue-api-token",
		Description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
		Regex:       generateUniqueTokenRegex(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`, true),

		Keywords: []string{
			"xkeysib-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("sendinblue", "xkeysib-"+secrets.NewSecret(hex("64"))+"-"+secrets.NewSecret(alphaNumeric("16"))),
	}
	return validate(r, tps, nil)
}
