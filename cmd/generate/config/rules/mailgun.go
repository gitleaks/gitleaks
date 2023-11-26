package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MailGunPrivateAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-private-api-token",
		Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
		Regex:       generateSemiGenericRegex([]string{"mailgun"}, `key-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailgun", "key-"+secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}

func MailGunPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-pub-key",
		Description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
		Regex:       generateSemiGenericRegex([]string{"mailgun"}, `pubkey-[a-f0-9]{32}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailgun", "pubkey-"+secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}

func MailGunSigningKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailgun-signing-key",
		Description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
		Regex:       generateSemiGenericRegex([]string{"mailgun"}, `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}`, true),

		Keywords: []string{
			"mailgun",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailgun", secrets.NewSecret(hex("32"))+"-00001111-22223333"),
	}
	return validate(r, tps, nil)
}
