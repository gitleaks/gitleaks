package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		RuleID:      "discord-api-token",
		Regex:       generateSemiGenericRegex([]string{"discord"}, hex("64"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		RuleID:      "discord-client-id",
		Regex:       generateSemiGenericRegex([]string{"discord"}, numeric("18"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", secrets.NewSecret(numeric("18"))),
	}
	return validate(r, tps, nil)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		RuleID:      "discord-client-secret",
		Regex:       generateSemiGenericRegex([]string{"discord"}, alphaNumericExtended("32"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", secrets.NewSecret(numeric("32"))),
	}
	return validate(r, tps, nil)
}
