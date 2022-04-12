package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func GoCardless() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "gocardless-api-token",
		Description: "GoCardless API token",
		Regex:       generateSemiGenericRegex([]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`),
		Keywords: []string{
			"live_",
			"gocardless",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("gocardless", "live_"+sampleExtendedAlphaNumeric40Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate gocardless-api-token")
		}
	}
	return &r
}
