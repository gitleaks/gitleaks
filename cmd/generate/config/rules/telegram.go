package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TelegramBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Telegram Bot API Token",
		RuleID:      "telegram-bot-api-token",
		SecretGroup: 1,
		Regex:       regexp.MustCompile(`(?i)(?:^|[^0-9])([0-9]{5,16}:A[a-zA-Z0-9_\-]{34})(?:$|[^a-zA-Z0-9_\-])`),
		Keywords: []string{
			"telegram",
			"api",
			"bot",
			"token",
			"url",
		},
	}

	// validate
	validToken := secrets.NewSecret(numeric("8") + ":A" + alphaNumericExtendedShort("34"))
	minToken := secrets.NewSecret(numeric("5") + ":A" + alphaNumericExtendedShort("34"))
	maxToken := secrets.NewSecret(numeric("16") + ":A" + alphaNumericExtendedShort("34"))
	tps := []string{
		// variable assigment
		generateSampleSecret("telegram", validToken),
		// URL contaning token
		generateSampleSecret("url", "https://api.telegram.org/bot"+validToken+"/sendMessage"),
		// object constructor
		`const bot = new Telegraf("` + validToken + `")`,
		// .env
		`API_TOKEN = ` + validToken,
		// YAML
		`bot: ` + validToken,
		// Token with min bot_id
		generateSampleSecret("telegram", minToken),
		// Token with max bot_id
		generateSampleSecret("telegram", maxToken),
	}

	tooSmallToken := secrets.NewSecret(numeric("4") + ":A" + alphaNumericExtendedShort("34"))
	tooBigToken := secrets.NewSecret(numeric("17") + ":A" + alphaNumericExtendedShort("34"))
	fps := []string{
		// Token with too small bot_id
		generateSampleSecret("telegram", tooSmallToken),
		// Token with too big bot_id
		generateSampleSecret("telegram", tooBigToken),
	}

	return validate(r, tps, fps)
}
