package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func RazorpayKeyID() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "razorpay-key-id",
		Description: "Detected a Razorpay Key ID, potentially compromising payment gateway access and exposing transaction data.",
		Regex:       utils.GenerateUniqueTokenRegex(`rzp_(?:live|test)_[a-zA-Z0-9]{14}`, false),
		Entropy:     2,
		Keywords: []string{
			"razorpay",
			"rzp_live",
			"rzp_test",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("razorpay", "rzp_test_"+secrets.NewSecret(utils.AlphaNumeric("14")))
	tps = append(tps, utils.GenerateSampleSecrets("razorpay", "rzp_live_"+secrets.NewSecret(utils.AlphaNumeric("14")))...)
	fps := []string{"nonMatchingToken := \"rxp_test_" + secrets.NewSecret(utils.AlphaNumeric("14")) + "\""}
	return utils.Validate(r, tps, fps)
}

func RazorpayKeySecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "razorpay-key-secret",
		Description: "Detected a Razorpay Key Secret, risking unauthorized payment operations and sensitive financial data exposure.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"razorpay"}, utils.AlphaNumeric("24"), true),
		Entropy:     3.5,
		Keywords: []string{
			"razorpay",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("razorpay", secrets.NewSecret(utils.AlphaNumeric("24")))
	return utils.Validate(r, tps, nil)
}
