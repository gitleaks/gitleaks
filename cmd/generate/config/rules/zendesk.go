package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ZendeskSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "zendesk-secret-key",
		Description: "Zendesk Secret Key",
		Regex:       generateSemiGenericRegex([]string{"zendesk"}, alphaNumeric("40")),
		SecretGroup: 1,
		Keywords: []string{
			"zendesk",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("zendesk", secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}
