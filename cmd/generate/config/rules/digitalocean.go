package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DigitalOceanPAT() *config.Rule {
	r := config.Rule{
		Description: "DigitalOcean Personal Access Token",
		RuleID:      "digitalocean-pat",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`),
		Keywords:    []string{"dop_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "dop_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}

func DigitalOceanOAuthToken() *config.Rule {
	r := config.Rule{
		Description: "DigitalOcean OAuth Access Token",
		RuleID:      "digitalocean-access-token",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`doo_v1_[a-f0-9]{64}`),
		Keywords:    []string{"doo_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "doo_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}

func DigitalOceanRefreshToken() *config.Rule {
	r := config.Rule{
		Description: "DigitalOcean OAuth Refresh Token",
		RuleID:      "digitalocean-refresh-token",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`),
		Keywords:    []string{"dor_v1_"},
	}

	tps := []string{
		generateSampleSecret("do", "dor_v1_"+secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
