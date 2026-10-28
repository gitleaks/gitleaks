package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func SquareAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-access-token",
		Description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
		// Production OAuth/access tokens are EAAA + 60 chars (64 total). Personal access
		// tokens use the sq0atp- prefix. Fixing the EAAA branch length avoids matching
		// short fragments of base64-encoded payloads — see #2093.
		Regex:    utils.GenerateUniqueTokenRegex(`(?:EAAA[\w-]{60}|sq0atp-[\w-]{22,43})`, false),
		Entropy:  2,
		Keywords: []string{"sq0atp-", "EAAA"},
		Allowlists: []*config.Allowlist{
			{
				// Common carriers of base64-encoded payloads where EAAA can appear
				// inside ZIP/Office archives or MIME attachments. See #2093.
				Paths: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\.(?:eml|mht|msg|xlsx|docx|pptx|zip|jar|war|ear|apk|ipa)$`),
				},
			},
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("square", "EAAA"+secrets.NewSecret(utils.AlphaNumericExtendedShort("60")))
	tps = append(tps,
		utils.GenerateSampleSecret("square", "sq0atp-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("22"))),
		"ARG token=sq0atp-812erere3wewew45678901",                                    // gitleaks:allow
		"ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E", // gitleaks:allow",
	)
	fps := []string{
		`aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00`,
		// Fragment of base64-encoded ZIP content; EAAA followed by fewer than 60
		// word chars should no longer trip the rule. See #2093.
		`mJeJ0b3bVQZu6P8AUEsHCFDBu3Q+EAAAWRAAAFBLAwQUAAgICAAYZxlbAAAAAAAAAAAAAAAAEwAA`,
	}
	return utils.Validate(r, tps, fps)
}

func SquareSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-secret",
		Description: "Square Secret",
		Regex:       utils.GenerateUniqueTokenRegex(`sq0csp-[\w-]{43}`, false),
		Entropy:     2,
		Keywords:    []string{"sq0csp-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("square", secrets.NewSecret(`sq0csp-[0-9A-Za-z\\-_]{43}`))
	tps = append(tps,
		`value: "sq0csp-0p9h7g6f4s3s3s3-4a3ardgwa6ADRDJDDKUFYDYDYDY"`, // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
