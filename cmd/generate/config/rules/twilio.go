package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Twilio() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Twilio API Key",
		RuleID:      "twilio-api-key",
		Regex:       regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Keywords:    []string{"twilio"},
	}

	// validate
	tps := []string{
		"twilioAPIKey := \"SK" + sampleHex32Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate twilio")
		}
	}
	return &r
}
