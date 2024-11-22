package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config/rule"
)

func BittrexAccessKey() *rule.Rule {
	// define rule
	r := rule.Rule{
		Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleID:      "bittrex-access-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true),
		Keywords:    []string{"bittrex"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bittrex", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}

func BittrexSecretKey() *rule.Rule {
	// define rule
	r := rule.Rule{
		Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleID:      "bittrex-secret-key",
		Regex:       utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true),

		Keywords: []string{"bittrex"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("bittrex", secrets.NewSecret(utils.AlphaNumeric("32")))
	return utils.Validate(r, tps, nil)
}
