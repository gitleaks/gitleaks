package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func AgeSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
		RuleID:      "age-secret-key",
		Regex:       regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
		Keywords:    []string{"AGE-SECRET-KEY-1"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("age", `AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ`) // gitleaks:allow
	return utils.Validate(r, tps, nil)
}
