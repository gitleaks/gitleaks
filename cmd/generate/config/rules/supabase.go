package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// https://supabase.com/docs/guides/getting-started/quickstarts/nextjs
func SupabaseServiceKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "supabase-service-key",
		Description: "Detected a Supabase Personal Access Token (PAT), which could allow unauthorized access to Supabase project management APIs.",
		Regex:       utils.GenerateUniqueTokenRegex(`sbp_[a-f0-9]{40}`, false),
		Entropy:     3.5,
		Keywords:    []string{"sbp_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("supabase", "sbp_"+secrets.NewSecret(utils.Hex("40")))
	fps := []string{
		`SUPABASE_PAT=sbp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, // placeholder, not real
	}
	return utils.Validate(r, tps, fps)
}
