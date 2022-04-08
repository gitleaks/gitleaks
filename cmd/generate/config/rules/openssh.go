package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func OpenSSH() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "SSH private key",
		RuleID:      "OPENSSH-PK",
		Regex:       regexp.MustCompile("-----BEGIN OPENSSH PRIVATE KEY-----"),
		Keywords:    []string{"-----BEGIN OPENSSH"},
	}

	// validate
	tps := []string{"-----BEGIN OPENSSH PRIVATE KEY-----"}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate OPENSSH")
		}
	}
	return &r
}
