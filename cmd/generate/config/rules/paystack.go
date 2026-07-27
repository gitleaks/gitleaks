package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PaystackSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "paystack-secret-key",
		Description: "Detected a Paystack Secret Key, risking unauthorized payment operations and exposure of sensitive financial transaction data.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"paystack"}, `sk_(?:test|live)_[a-z0-9]{40}`, true),
		Entropy:     2,
		Keywords: []string{
			"paystack",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("paystack", "sk_test_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	tps = append(tps, utils.GenerateSampleSecrets("paystack", "sk_live_"+secrets.NewSecret(utils.AlphaNumeric("40")))...)
	fps := []string{"nonMatchingToken := \"sk_test_" + secrets.NewSecret(utils.AlphaNumeric("40")) + "\""}
	return utils.Validate(r, tps, fps)
}

func PaystackPublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "paystack-public-key",
		Description: "Detected a Paystack Public Key, potentially exposing payment integration details and enabling unauthorized client-side operations.",
		Regex:       utils.GenerateUniqueTokenRegex(`pk_(?:test|live)_[a-z0-9]{40}`, false),
		Entropy:     2,
		Keywords: []string{
			"paystack",
			"pk_test",
			"pk_live",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("paystack", "pk_test_"+secrets.NewSecret(utils.AlphaNumeric("40")))
	tps = append(tps, utils.GenerateSampleSecrets("paystack", "pk_live_"+secrets.NewSecret(utils.AlphaNumeric("40")))...)
	fps := []string{"nonMatchingToken := \"px_test_" + secrets.NewSecret(utils.AlphaNumeric("40")) + "\""}
	return utils.Validate(r, tps, fps)
}
