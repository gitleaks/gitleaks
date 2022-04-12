package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Intercom() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Intercom API Token",
		RuleID:      "intercom-api-key",
		Regex:       generateSemiGenericRegex([]string{"intercom"}, extendedAlphaNumeric60),
		SecretGroup: 1,
		Keywords:    []string{"intercom"},
	}

	// validate
	tps := []string{
		generateSampleSecret("intercom", sampleExtendedAlphaNumeric60Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate intercom-api-key")
		}
	}

	return &r
}
