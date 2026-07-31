package rules

import (
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Sample values are assembled at runtime rather than written as literals so that
// secret scanners do not flag this file.
const (
	supabaseSecretPrefix = "sb_secret_"
	supabasePatPrefix    = "sbp_"
)

// SupabaseSecretKey matches the current-generation Supabase secret API key, the
// replacement for the legacy `service_role` JWT. It bypasses Row Level Security,
// so it is the highest-impact credential a Supabase project issues.
//
// Supabase documents the prefix but not the suffix, so the shape below comes from
// sampling real keys: `sb_secret_` is followed by 22 base64url characters (16
// random bytes) and an 8 character checksum segment. That is 31 characters total
// counting the separator, which `_` inside the character class already covers.
//
// The sibling `sb_publishable_` key is deliberately not covered: it is designed
// to ship in client-side code, so flagging it would be a false positive by
// definition.
func SupabaseSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "supabase-secret-key",
		Description: "Discovered a Supabase secret API key, potentially exposing a project's entire database, storage and auth by bypassing Row Level Security.",
		Regex:       utils.GenerateUniqueTokenRegex(`sb_secret_[a-zA-Z0-9_-]{31}`, false),
		Entropy:     3,
		Keywords:    []string{supabaseSecretPrefix},
	}

	// validate
	tps := utils.GenerateSampleSecrets("supabase", supabaseSecretPrefix+secrets.NewSecret(`[a-zA-Z0-9_-]{22}_[a-zA-Z0-9]{8}`))
	fps := []string{
		// A placeholder of the correct length must not fire.
		"SUPABASE_SECRET_KEY=" + supabaseSecretPrefix + strings.Repeat("x", 31),
		// Too short to be a real key.
		"SUPABASE_SECRET_KEY=" + supabaseSecretPrefix + strings.Repeat("a", 20),
		// The publishable key is public by design and is not this rule's concern.
		"SUPABASE_PUBLISHABLE_KEY=sb_publishable_" + secrets.NewSecret(`[a-zA-Z0-9]{22}_[a-zA-Z0-9]{8}`),
	}
	return utils.Validate(r, tps, fps)
}

// SupabasePersonalAccessToken matches the Supabase personal access token used by
// the Management API and the `supabase` CLI (`SUPABASE_ACCESS_TOKEN`). It is
// account-scoped rather than project-scoped, so a leak exposes every project the
// owner can reach.
//
// Real tokens appear both as `sbp_<40 hex>` and as a versioned `sbp_v0_<40 hex>`,
// so the version segment is optional here.
func SupabasePersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "supabase-personal-access-token",
		Description: "Identified a Supabase personal access token, which grants Management API control over every project owned by the account.",
		Regex:       utils.GenerateUniqueTokenRegex(`sbp_(?:v[0-9]_)?[a-f0-9]{40}`, false),
		Entropy:     3,
		Keywords:    []string{supabasePatPrefix},
	}

	// validate
	tps := utils.GenerateSampleSecrets("supabase", supabasePatPrefix+secrets.NewSecret(`[a-f0-9]{40}`))
	tps = append(tps, utils.GenerateSampleSecrets("supabase", supabasePatPrefix+"v0_"+secrets.NewSecret(`[a-f0-9]{40}`))...)
	fps := []string{
		// A placeholder of the correct length must not fire.
		"SUPABASE_ACCESS_TOKEN=" + supabasePatPrefix + strings.Repeat("0", 40),
		// Uppercase hex is not the issued format.
		"SUPABASE_ACCESS_TOKEN=" + supabasePatPrefix + strings.Repeat("A", 40),
		// Too short to be a real token.
		"SUPABASE_ACCESS_TOKEN=" + supabasePatPrefix + strings.Repeat("a1b2", 5),
	}
	return utils.Validate(r, tps, fps)
}
