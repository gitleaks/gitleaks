package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DigitalOceanPAT() *config.Rule {
	r := config.Rule{
		RuleID:      "digitalocean-pat",
		Description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
		Regex:       utils.GenerateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`, false),
		Entropy:     3,
		Keywords:    []string{"dop_v1_"},
	}

	tps := utils.GenerateSampleSecrets("do", "dop_v1_"+secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}

func DigitalOceanOAuthToken() *config.Rule {
	r := config.Rule{
		RuleID:      "digitalocean-access-token",
		Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
		Entropy:     3,
		Regex:       utils.GenerateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`, false),
		Keywords:    []string{"doo_v1_"},
	}

	tps := utils.GenerateSampleSecrets("do", "doo_v1_"+secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}

func DigitalOceanRefreshToken() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
		RuleID:      "digitalocean-refresh-token",

		Regex:    utils.GenerateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true),
		Keywords: []string{"dor_v1_"},
	}

	tps := utils.GenerateSampleSecrets("do", "dor_v1_"+secrets.NewSecret(utils.Hex("64")))
	return utils.Validate(r, tps, nil)
}
