package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PostHogPersonalAPIKey() *config.Rule {
	// Define Rule
	r := config.Rule{
		RuleID:      "posthog-personal-api-key",
		Description: "Detected a PostHog personal API key, which could lead to unauthorized access to PostHog analytics data and account settings.",
		Regex:       utils.GenerateUniqueTokenRegex(`phx_[a-zA-Z0-9_]{43,48}`, false),
		Entropy:     3.5,
		Keywords: []string{
			"phx_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("posthog-personal-api-key", "phx_"+secrets.NewSecret(`[a-zA-Z0-9_]{45}`))
	// Boundary lengths: shortest (43) and longest (48) accepted bodies.
	tps = append(tps,
		`POSTHOG_PERSONAL_API_KEY=phx_u8jzPde0IgxLd6GncfBAepfJBd0Kh8oOOL8dKLzd_oc`,
		`POSTHOG_PERSONAL_API_KEY=phx_J2isAjIhKtJ0RlgLKOmxgJTeKdNnFRIBXuDL7DxtpYlSXpfK`,
	)
	fps := []string{
		// Too short: body below the 43-character minimum.
		`POSTHOG_PERSONAL_API_KEY=phx_tHF4vUCsM_ehGAkWvj7FAc9QeWJKY40uvSwMFLZDe1`,
		`POSTHOG_PERSONAL_API_KEY=phx_short`,
		// Masked key as shown in the PostHog dashboard (phx_***1234).
		`POSTHOG_PERSONAL_API_KEY=phx_***1234`,
		// No word boundary before the prefix.
		`POSTHOG_PERSONAL_API_KEY=xphx_f8rESQedUStPKR0CsTy4Qwb8DwkNhFdnXsiVpzz63FfkC`,
		// Hyphen is not part of the key alphabet and neither run reaches 43 chars.
		`POSTHOG_PERSONAL_API_KEY=phx_zJr4i0B3JrTAwR4y9ojf-zJr4i0B3JrTAwR4y9ojf`,
	}
	return utils.Validate(r, tps, fps)
}
