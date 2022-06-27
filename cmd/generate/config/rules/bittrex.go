package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func BittrexAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Bittrex Access Key",
		RuleID:      "bittrex-access-key",
		Regex:       generateSemiGenericRegex([]string{"bittrex"}, alphaNumeric("32")),
		SecretGroup: 1,
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
		Description: "Bittrex Secret Key",
		RuleID:      "bittrex-secret-key",
		Regex:       generateSemiGenericRegex([]string{"bittrex"}, alphaNumeric("32")),
		SecretGroup: 1,
		Keywords:    []string{"bittrex"},
	}

	// validate
	tps := []string{
		generateSampleSecret("bittrex", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
