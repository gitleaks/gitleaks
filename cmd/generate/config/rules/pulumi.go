package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PulumiAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pulumi-api-token",
		Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
		Regex:       generateUniqueTokenRegex(`pul-[a-f0-9]{40}`, true),

		Keywords: []string{
			"pul-",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("pulumi-api-token", "pul-"+secrets.NewSecret(hex("40"))),
	}
	return validate(r, tps, nil)
}
