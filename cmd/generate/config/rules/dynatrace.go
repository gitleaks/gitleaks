package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Dynatrace() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Dynatrace API token",
		RuleID:      "dynatrace-api-token",
		Regex:       regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`),
		Keywords:    []string{"dynatrace"},
	}

	// validate
	tps := []string{
		generateSampleSecret("dynatrace", "dt0c01."+sampleAlphaNumeric24Token+"."+sampleAlphaNumeric64Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate dynatrace-api-token")
		}
	}
	return &r
}
