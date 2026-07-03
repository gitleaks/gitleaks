package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func BraintreeAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "braintree-access-token",
		Description: "Detected a Braintree Access Token, posing a risk to payment processing operations and exposing sensitive merchant financial data.",
		Regex:       utils.GenerateUniqueTokenRegex(`access_token\$(?:production|sandbox)\$[a-z0-9]{16}`, false),
		Entropy:     2,
		Keywords: []string{
			"braintree",
			"access_token$production$",
			"access_token$sandbox$",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("braintree", "access_token$sandbox$"+secrets.NewSecret(utils.AlphaNumeric("16")))
	tps = append(tps, utils.GenerateSampleSecrets("braintree", "access_token$production$"+secrets.NewSecret(utils.AlphaNumeric("16")))...)
	fps := []string{"nonMatchingToken := \"access_token$staging$" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\""}
	return utils.Validate(r, tps, fps)
}

func BraintreeTokenizationKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "braintree-tokenization-key",
		Description: "Detected a Braintree Tokenization Key, potentially exposing client-side payment tokenization and merchant account details.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:production|sandbox)_[a-z0-9]{8}_[a-z0-9]{16}`, false),
		Entropy:     2,
		Keywords: []string{
			"braintree",
			"production_",
			"sandbox_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("braintree", "sandbox_"+secrets.NewSecret(utils.AlphaNumeric("8"))+"_"+secrets.NewSecret(utils.AlphaNumeric("16")))
	tps = append(tps, utils.GenerateSampleSecrets("braintree", "production_"+secrets.NewSecret(utils.AlphaNumeric("8"))+"_"+secrets.NewSecret(utils.AlphaNumeric("16")))...)
	fps := []string{"nonMatchingToken := \"development_" + secrets.NewSecret(utils.AlphaNumeric("8")) + "_" + secrets.NewSecret(utils.AlphaNumeric("16")) + "\""}
	return utils.Validate(r, tps, fps)
}
