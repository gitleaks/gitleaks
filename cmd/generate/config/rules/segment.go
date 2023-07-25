package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SegmentPublicApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Segment Public API Token",
		RuleID:      "segment-public-api-token",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`sgp_[a-zA-Z0-9]{64}`),
		Keywords: []string{
			"sgp_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("segment", "sgp_"+secrets.NewSecret(alphaNumeric("64"))),
	}
	return validate(r, tps, nil)
}
