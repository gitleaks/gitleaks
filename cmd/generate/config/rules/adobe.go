package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func AdobeClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Adobe Client ID (Oauth Web)",
		RuleID:      "adobe-client-id",
		Regex:       generateSemiGenericRegex([]string{"adobe"}, hex32),
		SecretGroup: 1,
		Keywords:    []string{"adobe"},
	}

	// validate
	tps := []string{
		"adobeClient := \"" + sampleHex32Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate adobe-client-id")
		}
	}
	return &r
}

func AdobeClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Adobe Client Secret",
		RuleID:      "adobe-client-secret",
		Regex:       regexp.MustCompile(`(p8e-)(?i)[a-z0-9]{32}`),
		Keywords:    []string{"p8e-"},
	}

	// validate
	tps := []string{
		"adobeClient := \"p8e-" + sampleHex32Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate adobe-client-secret")
		}
	}
	return &r
}
