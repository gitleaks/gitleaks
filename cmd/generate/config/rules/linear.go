package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func LinearAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear API Token",
		RuleID:      "linear-api-key",
		Regex:       regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`),
		Keywords:    []string{"lin_api_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", "lin_api_"+sampleAlphaNumeric40Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate linear-api-key")
		}
	}

	return &r
}

func LinearClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Linear Client Secret",
		RuleID:      "linear-client-secret",
		Regex:       generateSemiGenericRegex([]string{"linear"}, hex32),
		Keywords:    []string{"linear"},
	}

	// validate
	tps := []string{
		generateSampleSecret("linear", sampleHex32Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate linear-client-secret")
		}
	}

	return &r
}
