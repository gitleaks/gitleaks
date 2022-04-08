package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func PKCS8() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "PKCS8 private key",
		RuleID:      "PKCS8-PK",
		Regex:       regexp.MustCompile("-----BEGIN PRIVATE KEY-----"),
		Keywords:    []string{"-----BEGIN PRIVATE"},
	}

	// validate
	tps := []string{"-----BEGIN PRIVATE KEY-----"}
	config := config.Config{}
	config.Rules = append(config.Rules, &r)
	d := detect.NewDetector(config)
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate PKCS8")
		}
	}

	return &r
}
