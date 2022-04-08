package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func AWS() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "AWS",
		RuleID:      "aws-access-token",
		Regex: regexp.MustCompile(
			"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
		Keywords: []string{
			"AKIA",
			"AGPA",
			"AIDA",
			"AROA",
			"AIPA",
			"ANPA",
			"ANVA",
			"ASIA",
		},
	}

	// validate
	tps := []string{"AWSToken := \"" + "AKIALALEMEL33243OLIB" + "\""}
	config := config.Config{}
	config.Rules = append(config.Rules, &r)
	d := detect.NewDetector(config)
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate AWS")
		}
	}

	return &r
}
