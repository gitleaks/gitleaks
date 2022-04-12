package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func LobPubAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Lob Publishable API Key",
		RuleID:      "lob-pub-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(test|live)_pub_[a-f0-9]{31}`),
		Keywords: []string{
			"test_pub",
			"live_pub",
			"_pub",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("lob", "test_pub_"+sampleHex31Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate lob-pub-api-key")
		}
	}

	return &r
}

func LobAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Lob API Key",
		RuleID:      "lob-api-key",
		Regex:       generateSemiGenericRegex([]string{"lob"}, `(live|test)_[a-f0-9]{35}`),
		Keywords: []string{
			"test_",
			"live_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("lob", "test_"+sampleHex35Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate lob-api-key")
		}
	}

	return &r
}
