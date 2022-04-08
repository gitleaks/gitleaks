package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func BitBucketClientID() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "BitBucket Client ID",
		RuleID:      "bitbucket-client-id",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, alphaNumeric32),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		"bitbucket := \"" + sampleAlphaNumeric32Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate bitbucket-client-id")
		}
	}
	return &r
}

func BitBucketClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "BitBucket Client Secret",
		RuleID:      "bitbucket-client-secret",
		Regex:       generateSemiGenericRegex([]string{"bitbucket"}, extendedAlphaNumeric64),
		SecretGroup: 1,
		Keywords:    []string{"bitbucket"},
	}

	// validate
	tps := []string{
		"bitbucket := \"" + sampleExtendedAlphaNumeric64Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate bitbucket-client-secret")
		}
	}
	return &r
}
