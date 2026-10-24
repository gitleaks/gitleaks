package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// Supabase issues two JWTs per project: `anon`, which is meant to be shipped to
// browsers, and `service_role`, which bypasses row level security and has full
// access to the project database. They are identical in shape, so the stock `jwt`
// rule matches both — flagging the public key and the secret one alike.
//
// The only thing separating them is the `role` claim in the base64 payload, which
// gitleaks surfaces on its second decoding pass. This rule therefore matches the
// decoded claim rather than the token, and requires --max-decode-depth >= 1.
//
// Keywords work here despite the secret living inside base64: detect.go rebuilds
// the keyword prefilter on every decode pass, so `service_role` is visible once the
// JWT payload is decoded. Empirically verified — see the PR for details.
func SupabaseServiceRoleKey() *config.Rule {
	r := config.Rule{
		RuleID:      "supabase-service-role-key",
		Description: "Detected a Supabase service_role key, which bypasses row level security and grants full access to the project database.",
		Regex:       regexp.MustCompile(`"role"\s*:\s*"service_role"`),
		Keywords:    []string{"service_role"},
	}

	// NOTE: utils.Validate builds a detector with MaxDecodeDepth 0, so these samples
	// are the DECODED payloads, not the tokens themselves. A JWT sample would never
	// be decoded and validation would fatal.
	tps := []string{
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"service_role","iat":1700000000,"exp":2000000000}`,
		`{"role": "service_role", "iss": "supabase"}`,
		`{"aud":"authenticated","role":"service_role"}`,
	}
	fps := []string{
		// The anon key — public, safe to ship, and the whole reason this rule exists.
		`{"iss":"supabase","ref":"abcdefghijklmnopqrst","role":"anon","iat":1700000000,"exp":2000000000}`,
		`{"role":"authenticated"}`,
		`{"role":"anon"}`,
	}
	return utils.Validate(r, tps, fps)
}
