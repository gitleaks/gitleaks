package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discord API key",
		RuleID:      "discord-api-token",
		Regex:       generateSemiGenericRegex([]string{"discord"}, hex("64")),
		SecretGroup: 1,
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
		Description: "Discord client ID",
		RuleID:      "discord-client-id",
		Regex:       generateSemiGenericRegex([]string{"discord"}, numeric("18")),
		SecretGroup: 1,
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
		Description: "Discord client secret",
		RuleID:      "discord-client-secret",
		Regex:       generateSemiGenericRegex([]string{"discord"}, alphaNumericExtended("32")),
		SecretGroup: 1,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		generateSampleSecret("discord", secrets.NewSecret(numeric("32"))),
	}
	return validate(r, tps, nil)
}
