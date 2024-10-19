package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func AgeSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "age-secret-key",
		Description: "Discovered a potential Age encryption tool secret key, risking data decryption and unauthorized access to sensitive information.",
		// TODO: This character range is confusing. Huh?
		Regex:    regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`),
		Entropy:  3,
		Keywords: []string{"AGE-SECRET-KEY-1"},
	}

	// validate
	tps := []string{
		`apiKey := "AGE-SECRET-KEY-1FDFPAKWWTNRY2FTQ22EKVUM67LZ48RQQFDNH0V90D6SVDKCSCDXSNP5KFA`, // gitleaks:allow
	}
	fps := []string{
		`apiKey := "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ`, // gitleaks:allow
	}
	return utils.Validate(r, tps, fps)
}
