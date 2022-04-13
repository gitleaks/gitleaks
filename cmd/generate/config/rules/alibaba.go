package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba AccessKey ID",
		RuleID:      "alibaba-access-key-id",
		Regex:       regexp.MustCompile(`(LTAI)(?i)[a-z0-9]{20}`),
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + sampleHex20Token + "\"",
	}
	return validate(r, tps)
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba Secret Key",
		RuleID:      "alibaba-secret-key",
		Regex: generateSemiGenericRegex([]string{"alibaba"},
			alphaNumeric30),
		SecretGroup: 1,
		Keywords:    []string{"alibaba"},
	}

	// validate
	tps := []string{
		"alibabaSecret Key:= \"" + sampleAlphaNumeric30Token + "\"",
	}
	return validate(r, tps)
}
