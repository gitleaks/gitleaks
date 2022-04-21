package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear API Token",
		RuleID:      "linear-api-key",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", "lin_api_"+secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear Client Secret",
		RuleID:      "linear-client-secret",
		Regex:       generateSemiGenericRegex([]string{"linear"}, hex("32")),
		Keywords:    []string{"linear"},
		SecretGroup: 1,
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
