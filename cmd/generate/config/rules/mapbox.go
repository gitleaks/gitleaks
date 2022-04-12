package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func MapBox() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "MapBox API token",
		RuleID:      "mapbox-api-token",
		Regex:       generateSemiGenericRegex([]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`),
		SecretGroup: 1,
		Keywords:    []string{"mapbox"},
	}

	// validate
	tps := []string{
		generateSampleSecret("mapbox", "pk."+sampleAlphaNumeric60Token+"."+sampleAlphaNumeric22Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate mapbox-api-token")
		}
	}
	return &r
}
