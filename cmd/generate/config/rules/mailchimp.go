package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MailChimp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailchimp-api-key",
		Description: "Mailchimp API key",
		Regex:       generateSemiGenericRegex([]string{"mailchimp"}, `[a-f0-9]{32}-us20`),
		SecretGroup: 1,
		Keywords: []string{
			"mailchimp",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailchimp", secrets.NewSecret(hex("32"))+"-us20"),
	}
	return validate(r, tps, nil)
}
