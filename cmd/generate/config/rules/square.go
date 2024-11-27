package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SquareAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-access-token",
		Description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`(?:EAAA|sq0atp-)[\w-]{22,60}`, false),
		Entropy:     2,
		Keywords:    []string{"sq0atp-", "EAAA"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("square", secrets.NewSecret(`(?:EAAA|sq0atp-)[\w-]{22,60}`))
	tps = append(tps,
		"ARG token=sq0atp-812erere3wewew45678901",                                    // gitleaks:allow
		"ARG token=EAAAlsBxkkVgvmr7FasTFbM6VUGZ31EJ4jZKTJZySgElBDJ_wyafHuBFquFexY7E", // gitleaks:allow",
	)
	fps := []string{
		`aws-cli@sha256:eaaa7b11777babe28e6133a8b19ff71cea687e0d7f05158dee95a71f76ce3d00`,
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
