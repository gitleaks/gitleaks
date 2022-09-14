package rules

import (
	"math/rand"
	"regexp"
	"strconv"

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
	token := secrets.NewSecret(numeric(strconv.Itoa(rand.Intn(11)+5)) + ":A" + alphaNumericExtendedShort("34"))
	tps := []string{
		// variable assigment
		generateSampleSecret("telegram", token),
		// URL contaning token
		generateSampleSecret("url", "https://api.telegram.org/bot"+token+"/sendMessage"),
		// object constructor
		`const bot = new Telegraf("` + token + `")`,
		// .env
		`API_TOKEN = ` + token,
		// YAML
		`bot: ` + token,
	}
	return validate(r, tps, nil)
}
