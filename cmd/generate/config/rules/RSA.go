package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func RSA() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "RSA private key",
		RuleID:      "RSA-PK",
		Regex:       regexp.MustCompile("-----BEGIN RSA PRIVATE KEY-----"),
		Keywords:    []string{"-----BEGIN RSA"},
	}

	// validate
	tps := []string{"-----BEGIN RSA PRIVATE KEY-----"}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate RSA")
		}
	}
	return &r
}
