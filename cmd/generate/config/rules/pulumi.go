package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func PulumiAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pulumi-api-token",
		Description: "Pulumi API token",
		Regex:       generateUniqueTokenRegex(`pul-[a-f0-9]{40}`),
		SecretGroup: 1,
		Keywords: []string{
			"pul-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("pulumi-api-token", "pul-"+sampleHex40Token),
	}
	return validate(r, tps)
}
