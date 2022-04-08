package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func AsanaClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Asana Client ID",
		RuleID:      "asana-client-id",
		Regex:       generateSemiGenericRegex([]string{"asana"}, numeric16),
		SecretGroup: 1,
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		"asanaKey := \"" + sampleNumeric16 + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate asana-client-id")
		}
	}
	return &r
}

func AsanaClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Asana Client Secret",
		RuleID:      "asana-client-secret",
		Regex:       generateSemiGenericRegex([]string{"asana"}, alphaNumeric32),
		Keywords:    []string{"asana"},
	}

	// validate
	tps := []string{
		"asanaKey := \"" + sampleAlphaNumeric32Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate asana-client-secret")
		}
	}
	return &r
}
