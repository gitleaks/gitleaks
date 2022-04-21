package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba AccessKey ID",
		RuleID:      "alibaba-access-key-id",
		Regex:       generateUniqueTokenRegex(`(LTAI)(?i)[a-z0-9]{20}`),
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + secrets.NewSecret(hex("20")) + "\"",
	}
	return validate(r, tps, nil)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba Secret Key",
		RuleID:      "alibaba-secret-key",
		Regex: generateSemiGenericRegex([]string{"alibaba"},
			alphaNumeric("30")),
		SecretGroup: 1,
		Keywords:    []string{"alibaba"},
	}

	// validate
	tps := []string{
		generateSampleSecret("alibaba", secrets.NewSecret(alphaNumeric("30"))),
	}
	return validate(r, tps, nil)
}
