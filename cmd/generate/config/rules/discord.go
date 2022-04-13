package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord API key",
		RuleID:      "discord-api-token",
		Regex:       generateSemiGenericRegex([]string{"discord"}, hex64),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleHex64Token),
	}
	return validate(r, tps)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord client ID",
		RuleID:      "discord-client-id",
		Regex:       generateSemiGenericRegex([]string{"discord"}, numeric18),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleNumeric18),
	}
	return validate(r, tps)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord client secret",
		RuleID:      "discord-client-secret",
		Regex:       generateSemiGenericRegex([]string{"discord"}, extendedAlphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", sampleExtendedAlphaNumeric32Token),
	}
	return validate(r, tps)
}
