package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TelegramBotToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
		RuleID:      "telegram-bot-api-token",

		Regex: regexp.MustCompile(`(?i:telegr(?:[0-9a-z\(-_\t .\\]{0,40})(?:[\s|']|[\s|"]){0,3})(?:=|\|\|:|<=|=>|:|\?=|\()(?:'|\"|\s|=|\x60){0,5}([0-9]{5,16}:A[a-z0-9_\-]{34})(?:['|\"|\n|\r|\s|\x60|;|\\]|$)`),
		Keywords: []string{
			"telegr",
		},
	}

	// validate
	var (
		validToken = secrets.NewSecret(utils.Numeric("8") + ":A" + utils.AlphaNumericExtendedShort("34"))
		minToken   = secrets.NewSecret(utils.Numeric("5") + ":A" + utils.AlphaNumericExtendedShort("34"))
		maxToken   = secrets.NewSecret(utils.Numeric("16") + ":A" + utils.AlphaNumericExtendedShort("34"))
		// xsdWithToken = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="` + Numeric("5") + `:A` + AlphaNumericExtendedShort("34") + `"/>`)
	)
	tps := []string{
		// variable assignment
		utils.GenerateSampleSecret("telegram", validToken),
		// URL containing token TODO add another url based rule
		// GenerateSampleSecret("url", "https://api.telegram.org/bot"+validToken+"/sendMessage"),
		// object constructor
		`const bot = new Telegraf("` + validToken + `")`,
		// .env
		`TELEGRAM_API_TOKEN = ` + validToken,
		// YAML
		`telegram bot: ` + validToken,
		// Token with min bot_id
		utils.GenerateSampleSecret("telegram", minToken),
		// Token with max bot_id
		utils.GenerateSampleSecret("telegram", maxToken),
		// Valid token in XSD document TODO separate rule for this
		// GenerateSampleSecret("telegram", xsdWithToken),
	}

	var (
		tooSmallToken                = secrets.NewSecret(utils.Numeric("4") + ":A" + utils.AlphaNumericExtendedShort("34"))
		tooBigToken                  = secrets.NewSecret(utils.Numeric("17") + ":A" + utils.AlphaNumericExtendedShort("34"))
		xsdAgencyIdentificationCode1 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm`+utils.Numeric("5")+":AgencyIdentificationCodeContentType") + `"/>`
		xsdAgencyIdentificationCode2 = secrets.NewSecret(`token:"clm` + utils.Numeric("5") + `:AgencyIdentificationCodeContentType"`)
		xsdAgencyIdentificationCode3 = secrets.NewSecret(`<xsd:element name="AgencyIdentificationCode" type="clm` + utils.Numeric("8") + `:AgencyIdentificationCodeContentType"/>`)
		prefixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:Ahello` + utils.AlphaNumericExtendedShort("34") + `\"`)
		prefixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:A-some-other-thing-` + utils.AlphaNumericExtendedShort("34") + `\"`)
		prefixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:A_` + utils.AlphaNumericExtendedShort("34") + `\"`)
		suffixedToken1               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:A` + utils.AlphaNumericExtendedShort("34") + `hello\"`)
		suffixedToken2               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:A` + utils.AlphaNumericExtendedShort("34") + `-some-other-thing\"`)
		suffixedToken3               = secrets.NewSecret(`telegram_api_token = \"` + utils.Numeric("8") + `:A_` + utils.AlphaNumericExtendedShort("34") + `_\"`)
	)
	fps := []string{
		// Token with too small bot_id
		utils.GenerateSampleSecret("telegram", tooSmallToken),
		// Token with too big bot_id
		utils.GenerateSampleSecret("telegram", tooBigToken),
		// XSD file containing the string AgencyIdentificationCodeContentType
		utils.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode1),
		utils.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode2),
		utils.GenerateSampleSecret("telegram", xsdAgencyIdentificationCode3),
		// Prefix and suffix variations that shouldn't match
		utils.GenerateSampleSecret("telegram", prefixedToken1),
		utils.GenerateSampleSecret("telegram", prefixedToken2),
		utils.GenerateSampleSecret("telegram", prefixedToken3),
		utils.GenerateSampleSecret("telegram", suffixedToken1),
		utils.GenerateSampleSecret("telegram", suffixedToken2),
		utils.GenerateSampleSecret("telegram", suffixedToken3),
	}

	return utils.Validate(r, tps, fps)
}
