package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost API token",
		RuleID:      "easypost-api-token",
		Regex:       regexp.MustCompile(`EZAK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZAK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZAK", "EZAK"+sampleAlphaNumeric54Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate easypost-api-token")
		}
	}
	return &r
}

func EasyPostTestAPI() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "EasyPost test API token",
		RuleID:      "easypost-test-api-token",
		Regex:       regexp.MustCompile(`EZTK(?i)[a-z0-9]{54}`),
		Keywords:    []string{"EZTK"},
	}

	// validate
	tps := []string{
		generateSampleSecret("EZTK", "EZTK"+sampleAlphaNumeric54Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate easypost-test-api-token")
		}
	}
	return &r
}
