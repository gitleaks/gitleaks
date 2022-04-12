package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func FastlyAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Fastly API key",
		RuleID:      "fastly-api-token",
		Regex:       generateSemiGenericRegex([]string{"fastly"}, extendedAlphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"fastly"},
	}

	// validate
	tps := []string{
		generateSampleSecret("fastly", sampleExtendedAlphaNumeric32Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate fastly-api-token")
		}
	}
	return &r
}
