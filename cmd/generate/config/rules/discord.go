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

func DiscordBotToken() *config.Rule {
	// Discord bot tokens consist of a base64url-encoded bot ID, timestamp and
	// HMAC separated by dots. See https://discord.com/developers/docs/reference#authentication
	r := config.Rule{
		RuleID:      "discord-bot-token",
		Description: "Identified a Discord bot token, which could allow unauthorized access to a Discord bot account.",
		Regex:       utils.GenerateUniqueTokenRegex(`[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}`, false),
		Entropy:     3,
	}

	// validate
	tps := []string{
		"MTIwMTE0MDk0MDQ2Nzg3MTc1NA.GIA1aR.l4cyaDp557_lJ_AV_wFHanBKwFJlB1KOxfKG6I",
	}
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
