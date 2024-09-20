package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		RuleID:      "discord-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Hex("64"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("discord", secrets.NewSecret(utils.Hex("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		RuleID:      "discord-client-id",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Numeric("18"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("discord", secrets.NewSecret(utils.Numeric("18"))),
	}
	return utils.Validate(r, tps, nil)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		RuleID:      "discord-client-secret",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.AlphaNumericExtended("32"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("discord", secrets.NewSecret(utils.Numeric("32"))),
	}
	return utils.Validate(r, tps, nil)
}
