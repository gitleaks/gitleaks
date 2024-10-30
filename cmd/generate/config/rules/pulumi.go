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
		Regex:       utils.GenerateUniqueTokenRegex(`pul-[a-f0-9]{40}`, false),
		Entropy:     2,
		Keywords: []string{
			"pul-",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("pulumi-api-token", "pul-"+secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		`                        <img src="./assets/vipul-f0eb1acf0da84c06a50c5b2c59932001997786b176dec02bd16128ee9ea83628.png" alt="" class="w-16 h-16 rounded-full">`,
	}
	return utils.Validate(r, tps, fps)
}
