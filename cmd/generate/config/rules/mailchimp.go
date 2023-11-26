package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MailChimp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailchimp-api-key",
		Description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
		Regex:       generateSemiGenericRegex([]string{"mailchimp"}, `[a-f0-9]{32}-us20`, true),

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
