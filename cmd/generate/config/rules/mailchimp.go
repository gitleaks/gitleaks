package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func MailChimp() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "mailchimp-api-key",
		Description: "Mailchimp API key",
		Regex:       generateSemiGenericRegex([]string{"mailchimp"}, `[a-f0-9]{32}-us20`),
		SecretGroup: 1,
		Keywords: []string{
			"mailchimp",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("mailchimp", sampleHex32Token+"-us20"),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate mailchimp-api-key")
		}
	}
	return &r
}
