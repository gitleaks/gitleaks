package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DiscordAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-api-token",
		Description: "Detected a Discord API key, potentially compromising communication channels and user data privacy on Discord.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Hex("64"), true),
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}

func DiscordClientID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-id",
		Description: "Identified a Discord client ID, which may lead to unauthorized integrations and data exposure in Discord applications.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.Numeric("18"), true),
		Entropy:     2,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecret(utils.Numeric("18")))
	fps := []string{
		// Low entropy
		`discord=000000000000000000`,
	}
	return utils.Validate(r, tps, fps)
}

func DiscordClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "discord-client-secret",
		Description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"discord"}, utils.AlphaNumericExtended("32"), true),
		Entropy:     2,
		Keywords:    []string{"discord"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("discord", secrets.NewSecret(utils.Numeric("32")))
	fps := []string{
		// Low entropy
		`discord=00000000000000000000000000000000`,
		// TODO:
		//`discord=01234567890123456789012345678901`,
	}
	return utils.Validate(r, tps, fps)
}
