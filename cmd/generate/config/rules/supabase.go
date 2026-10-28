package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SupabaseSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "supabase-secret-key",
		Description: "Uncovered a Supabase Secret API Key, which bypasses Row Level Security and grants full database and administrative access.",
		Regex:       utils.GenerateUniqueTokenRegex(`sb_secret_[a-zA-Z0-9_-]{31}`, false),
		Entropy:     3.5,
		Keywords: []string{
			"sb_secret_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("supabase", "sb_secret_"+secrets.NewSecret(utils.AlphaNumeric("22"))+"_"+secrets.NewSecret(utils.AlphaNumeric("8")))
	fps := []string{
		"sb_publishable_N7UND0UgjKTVK-Uodkm0Hg_xSvEMXXX",
	}
	return utils.Validate(r, tps, fps)
}

func SupabasePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "supabase-personal-access-token",
		Description: "Identified a Supabase Personal Access Token, which grants account-wide management access across all projects.",
		Regex:       utils.GenerateUniqueTokenRegex(`sbp_(?:v[0-9]+_)?[a-fA-F0-9]{40}`, false),
		Entropy:     3.5,
		Keywords: []string{
			"sbp_",
		},
	}

	// validate
	tps := append(
		utils.GenerateSampleSecrets("supabase", "sbp_"+secrets.NewSecret(utils.Hex("40"))),
		utils.GenerateSampleSecrets("supabase", "sbp_v0_"+secrets.NewSecret(utils.Hex("40")))...,
	)
	fps := []string{
		"sbp_invalid_token",
	}
	return utils.Validate(r, tps, fps)
}
