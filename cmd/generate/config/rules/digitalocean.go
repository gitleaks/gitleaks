package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DigitalOceanPAT() *config.Rule {
	r := config.Rule{
		Description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
		RuleID:      "digitalocean-pat",
		Regex:       utils.GenerateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`, true),
		Keywords:    []string{"dop_v1_"},
	}

	tps := []string{
		utils.GenerateSampleSecret("do", "dop_v1_"+secrets.NewSecret(utils.Hex("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func DigitalOceanOAuthToken() *config.Rule {
	r := config.Rule{
		Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
		RuleID:      "digitalocean-access-token",

		Regex:    utils.GenerateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`, true),
		Keywords: []string{"doo_v1_"},
	}

	tps := []string{
		utils.GenerateSampleSecret("do", "doo_v1_"+secrets.NewSecret(utils.Hex("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func DigitalOceanRefreshToken() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
		RuleID:      "digitalocean-refresh-token",

		Regex:    utils.GenerateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true),
		Keywords: []string{"dor_v1_"},
	}

	tps := []string{
		utils.GenerateSampleSecret("do", "dor_v1_"+secrets.NewSecret(utils.Hex("64"))),
	}
	return utils.Validate(r, tps, nil)
}
