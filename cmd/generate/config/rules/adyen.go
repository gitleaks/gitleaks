package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AdyenAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adyen-api-key",
		Description: "Detected an Adyen API key, potentially compromising payment processing operations and exposing sensitive financial data.",
		Regex:       utils.GenerateUniqueTokenRegex(`AQE[a-z0-9]{5,}\.[-a-zA-Z0-9_=]{50,80}`, false),
		Entropy:     2,
		Keywords: []string{
			"adyen",
			"AQE",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adyen", "AQEyhmfx."+secrets.NewSecret(utils.AlphaNumericExtended("60")))
	fps := []string{"nonMatchingToken := \"AXE" + secrets.NewSecret(utils.AlphaNumeric("30")) + "\""}
	return utils.Validate(r, tps, fps)
}

func AdyenClientKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "adyen-client-key",
		Description: "Detected an Adyen client key, which could expose client-side payment integrations and allow unauthorized transaction initiation.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:test|live)_[a-zA-Z0-9]{30,40}`, false),
		Entropy:     2,
		Keywords: []string{
			"adyen",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("adyen", "test_"+secrets.NewSecret(utils.AlphaNumeric("34")))
	tps = append(tps, utils.GenerateSampleSecrets("adyen", "live_"+secrets.NewSecret(utils.AlphaNumeric("34")))...)
	fps := []string{"nonMatchingToken := \"prod_" + secrets.NewSecret(utils.AlphaNumeric("34")) + "\""}
	return utils.Validate(r, tps, fps)
}
