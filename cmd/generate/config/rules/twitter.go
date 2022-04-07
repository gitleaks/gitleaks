package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Twitter() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "twitter",
		RuleID:      "twitter",
		Regex: generateSemiGenericRegex([]string{"twitter"},
			hex+"{35,44}"),
		SecretGroup: 1,
		Keywords:    []string{"twitter"},
	}

	// validate
	tps := []string{"twitterToken := \"" + sampleHex32Token + "aaaa\""}
	config := config.Config{}
	config.Rules = append(config.Rules, &r)
	d := detect.NewDetector(config)
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate twitter")
		}
	}

	return &r
}
