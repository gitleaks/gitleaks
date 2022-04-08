package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Databricks() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Databricks API token",
		RuleID:      "databricks-api-token",
		Regex:       regexp.MustCompile(`dapi[a-h0-9]{32}`),
		Keywords:    []string{"dapi"},
	}

	// validate
	tps := []string{
		generateSampleSecret("databricks", "dapi"+sampleHex32Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate databricks-api-token")
		}
	}
	return &r
}
