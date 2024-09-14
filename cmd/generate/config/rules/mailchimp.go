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
		Regex:       generateSemiGenericRegex([]string{"MailchimpSDK.initialize", "mailchimp"}, hex("32")+`-us\d\d`, true),

		Keywords: []string{
			"mailchimp",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailchimp", secrets.NewSecret(hex("32"))+"-us20"),
		`mailchimp_api_key: cefa780880ba5f5696192a34f6292c35-us18`, // gitleaks:allow
		`MAILCHIMPE_KEY = "b5b9f8e50c640da28993e8b6a48e3e53-us18"`, // gitleaks:allow
	}
	fps := []string{
		// False Negative
		`MailchimpSDK.initialize(token: 3012a5754bbd716926f99c028f7ea428-us18)`, // gitleaks:allow
	}
	return validate(r, tps, fps)
}
