package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DigitalOceanPAT() *config.Rule {
	r := config.Rule{
		Description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
		RuleID:      "digitalocean-pat",
		Regex:       generateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`, true),
		Keywords:    []string{"dop_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "dop_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}

func DigitalOceanOAuthToken() *config.Rule {
	r := config.Rule{
		Description: "Found a DigitalOcean OAuth Access Token, risking unauthorized cloud resource access and data compromise.",
		RuleID:      "digitalocean-access-token",

		Regex:    generateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`, true),
		Keywords: []string{"doo_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "doo_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}

func DigitalOceanRefreshToken() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
		RuleID:      "digitalocean-refresh-token",

		Regex:    generateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true),
		Keywords: []string{"dor_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "dor_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
