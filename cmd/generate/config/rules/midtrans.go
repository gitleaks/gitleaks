package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MidtransServerKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "midtrans-server-key",
		Description: "Detected a Midtrans Server Key, posing a risk to payment processing integrity and exposing sensitive transaction data.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:SB-)?Mid-server-[a-zA-Z0-9]{18,28}`, false),
		Entropy:     2,
		Keywords: []string{
			"midtrans",
			"mid-server-",
			"sb-mid-server-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("midtrans", "SB-Mid-server-"+secrets.NewSecret(utils.AlphaNumeric("24")))
	tps = append(tps, utils.GenerateSampleSecrets("midtrans", "Mid-server-"+secrets.NewSecret(utils.AlphaNumeric("24")))...)
	fps := []string{"nonMatchingToken := \"Mid-client-" + secrets.NewSecret(utils.AlphaNumeric("24")) + "\""}
	return utils.Validate(r, tps, fps)
}

func MidtransClientKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "midtrans-client-key",
		Description: "Detected a Midtrans Client Key, potentially exposing client-side payment integration details and enabling unauthorized transaction initiation.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:SB-)?Mid-client-[a-zA-Z0-9]{18,28}`, false),
		Entropy:     2,
		Keywords: []string{
			"midtrans",
			"mid-client-",
			"sb-mid-client-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("midtrans", "SB-Mid-client-"+secrets.NewSecret(utils.AlphaNumeric("24")))
	tps = append(tps, utils.GenerateSampleSecrets("midtrans", "Mid-client-"+secrets.NewSecret(utils.AlphaNumeric("24")))...)
	fps := []string{"nonMatchingToken := \"Mid-invalid-" + secrets.NewSecret(utils.AlphaNumeric("24")) + "\""}
	return utils.Validate(r, tps, fps)
}
