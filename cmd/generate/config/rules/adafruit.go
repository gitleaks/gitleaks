package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdafruitAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a potential Adafruit API Key, which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:      "adafruit-api-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"adafruit"}, utils.AlphaNumericExtendedShort("32"), true),
		Keywords:    []string{"adafruit"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adafruit", secrets.NewSecret(utils.AlphaNumericExtendedShort("32")))
	tps = append(tps,
		// Unquoted secrets followed by delimiters other than a quote,
		// whitespace, ';', or the end of the line. See #2354.
		`https://api.example.test/v1/items?adafruit_key=ab3de5fg7hj9kl1mn3pq5rs7tu9vw1xy&limit=10`,
		`ADAFRUIT_KEY=ab3de5fg7hj9kl1mn3pq5rs7tu9vw1xy,`,
		`connect(adafruit_key=ab3de5fg7hj9kl1mn3pq5rs7tu9vw1xy)`,
		`{adafruit_key: ab3de5fg7hj9kl1mn3pq5rs7tu9vw1xy}`,
	)
	return utils.Validate(r, tps, nil)
}
