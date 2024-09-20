package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PulumiAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pulumi-api-token",
		Description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
		Regex:       utils.GenerateUniqueTokenRegex(`pul-[a-f0-9]{40}`, true),

		Keywords: []string{
			"pul-",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("pulumi-api-token", "pul-"+secrets.NewSecret(utils.Hex("40"))),
	}
	return utils.Validate(r, tps, nil)
}
