package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Contentful() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Contentful delivery API token",
		RuleID:      "contentful-delivery-api-token",
		Regex: generateSemiGenericRegex([]string{"contentful"},
			`[a-z0-9\-=_]{43}`),
		SecretGroup: 1,
		Keywords:    []string{"contentful"},
	}

	// validate
	tps := []string{
		generateSampleSecret("contentful", sampleExtendedAlphaNumeric43Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate contentful-delivery-api-token")
		}
	}
	return &r
}
