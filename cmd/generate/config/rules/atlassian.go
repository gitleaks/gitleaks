package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Atlassian() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Atlassian API token",
		RuleID:      "atlassian-api-token",
		Regex:       generateSemiGenericRegex([]string{"atlassian"}, alphaNumeric24),
		SecretGroup: 1,
		Keywords:    []string{"atlassian"},
	}

	// validate
	tps := []string{
		"atlassian:= \"" + sampleAlphaNumeric24Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate atlassian-api-token")
		}
	}
	return &r
}
