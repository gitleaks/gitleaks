package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Clojars API token",
		RuleID:      "clojars-api-token",
		Regex:       regexp.MustCompile(`(CLOJARS_)(?i)[a-z0-9]{60}`),
		Keywords:    []string{"clojars"},
	}

	// validate
	tps := []string{
		"clojarsAPIToken := \"CLOJARS_" + sampleAlphaNumeric60Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate clojars-api-token")
		}
	}
	return &r
}
