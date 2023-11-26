package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func BittrexAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleID:      "bittrex-access-key",
		Regex:       generateSemiGenericRegex([]string{"bittrex"}, alphaNumeric("32"), true),
		Keywords:    []string{"bittrex"},
	}

	// validate
	tps := []string{
		generateSampleSecret("bittrex", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}

func BittrexSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleID:      "bittrex-secret-key",
		Regex:       generateSemiGenericRegex([]string{"bittrex"}, alphaNumeric("32"), true),

		Keywords: []string{"bittrex"},
	}

	// validate
	tps := []string{
		generateSampleSecret("bittrex", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
