package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func Gitlab() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Gitlab Personal Access Token",
		RuleID:      "gitlab-pat",
		Regex:       regexp.MustCompile(`glpat-[0-9a-zA-Z\-\_]{20}`),
		Keywords:    []string{"glpat-"},
	}

	// validate
	tps := []string{"gitlabPAT := \"glpat-" + sampleAlphaNumeric20Token + "\""}
	config := config.Config{}
	config.Rules = append(config.Rules, &r)
	d := detect.NewDetector(config)
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate gitlab-pat")
		}
	}

	return &r
}
