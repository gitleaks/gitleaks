package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Hashicorp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "HashiCorp Terraform user/org API token",
		RuleID:      "hashicorp-tf-api-token",
		Regex:       regexp.MustCompile(`(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`),
		Keywords:    []string{"atlasv1"},
	}

	// validate
	tps := []string{
		generateSampleSecret("hashicorpToken", sampleHex14Token+".atlasv1."+sampleExtendedAlphaNumeric64Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate hashicorp-tf-api-token")
		}
	}
	return &r
}
