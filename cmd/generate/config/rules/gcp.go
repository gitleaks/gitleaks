package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// TODO this one could probably use some work
func GCPServiceAccount() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Google (GCP) Service-account",
		RuleID:      "gcp-service-account",
		Regex:       regexp.MustCompile(`\"type\": \"service_account\"`),
		Keywords:    []string{`\"type\": \"service_account\"`},
	}

	// validate
	tps := []string{
		`"type": "service_account"`,
	}
	config := config.Config{}
	config.Rules = append(config.Rules, &r)
	d := detect.NewDetector(config)
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate service account")
		}
	}

	return &r
}
