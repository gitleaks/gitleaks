package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Beamer() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Beamer API token",
		RuleID:      "beamer-api-token",
		SecretGroup: 1,
		Regex: generateSemiGenericRegex([]string{"beamer"},
			`b_[a-z0-9=_\-]{44}`),
		Keywords: []string{"beamer"},
	}

	// validate
	tps := []string{
		"beamer := \"b_" + sampleAlphaNumeric32Token + "-_=_xxxxxxxx\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate beamer-api-token")
		}
	}
	return &r
}
