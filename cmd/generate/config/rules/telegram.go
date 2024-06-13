package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TelegramBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
		RuleID:      "telegram-bot-api-token",

		Regex: regexp.MustCompile(`(?i:(?:telegr)(?:[0-9a-z\(-_\t .\\]{0,40})(?:[\s|']|[\s|"]){0,3})(?:=|\|\|:|<=|=>|:|\?=|\()(?:'|\"|\s|=|\x60){0,5}([0-9]{5,16}:A[a-z0-9_\-]{34})(?:['|\"|\n|\r|\s|\x60|;|\\]|$)`),
		Keywords: []string{
			"telegr",
		},
	}

	// validate
	var (
		validToken = secrets.NewSecret(numeric("8") + ":A" + alphaNumericExtendedShort("34"))
		minToken   = secrets.NewSecret(numeric("5") + ":A" + alphaNumericExtendedShort("34"))
		maxToken   = secrets.NewSecret(numeric("16") + ":A" + alphaNumericExtendedShort("34"))
		// xsdWithToken = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="` + numeric("5") + `:A` + alphaNumericExtendedShort("34") + `"/>`)
	)
	tps := []string{
		// variable assignment
		generateSampleSecret("telegram", validToken),
		// URL containing token TODO add another url based rule
		// generateSampleSecret("url", "https://api.telegram.org/bot"+validToken+"/sendMessage"),
		// object constructor
		`const bot = new Telegraf("` + validToken + `")`,
		// .env
		`TELEGRAM_API_TOKEN = ` + validToken,
		// YAML
		`telegram bot: ` + validToken,
		// Token with min bot_id
		generateSampleSecret("telegram", minToken),
		// Token with max bot_id
		generateSampleSecret("telegram", maxToken),
		// Valid token in XSD document TODO separate rule for this
		// generateSampleSecret("telegram", xsdWithToken),
	}

	var (
		tooSmallToken                = secrets.NewSecret(numeric("4") + ":A" + alphaNumericExtendedShort("34"))
		tooBigToken                  = secrets.NewSecret(numeric("17") + ":A" + alphaNumericExtendedShort("34"))
		xsdAgencyIdentificationCode1 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm`+numeric("5")+":AgencyIdentificationCodeContentType") + `"/>`
		xsdAgencyIdentificationCode2 = secrets.NewSecret(`token:"clm` + numeric("5") + `:AgencyIdentificationCodeContentType"`)
		xsdAgencyIdentificationCode3 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm` + numeric("8") + `:AgencyIdentificationCodeContentType"/>`)
		prefixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:Ahello` + alphaNumericExtendedShort("34") + `\"`)
		prefixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:A-some-other-thing-` + alphaNumericExtendedShort("34") + `\"`)
		prefixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:A_` + alphaNumericExtendedShort("34") + `\"`)
		suffixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:A` + alphaNumericExtendedShort("34") + `hello\"`)
		suffixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:A` + alphaNumericExtendedShort("34") + `-some-other-thing\"`)
		suffixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + numeric("8") + `:A_` + alphaNumericExtendedShort("34") + `_\"`)
	)
	fps := []string{
		// Token with too small bot_id
		generateSampleSecret("telegram", tooSmallToken),
		// Token with too big bot_id
		generateSampleSecret("telegram", tooBigToken),
		// XSD file containing the string AgencyIdentificationCodeContentType
		generateSampleSecret("telegram", xsdAgencyIdentificationCode1),
		generateSampleSecret("telegram", xsdAgencyIdentificationCode2),
		generateSampleSecret("telegram", xsdAgencyIdentificationCode3),
		// Prefix and suffix variations that shouldn't match
		generateSampleSecret("telegram", prefixedToken1),
		generateSampleSecret("telegram", prefixedToken2),
		generateSampleSecret("telegram", prefixedToken3),
		generateSampleSecret("telegram", suffixedToken1),
		generateSampleSecret("telegram", suffixedToken2),
		generateSampleSecret("telegram", suffixedToken3),
	}

	return validate(r, tps, fps)
}
