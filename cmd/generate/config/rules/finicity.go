package rules

import (
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func FinicityClientSecret() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity Client Secret",
		RuleID:      "finicity-client-secret",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, alphaNumeric20),
		SecretGroup: 1,
		Keywords:    []string{"finicity"},
	}

	// validate
	tps := []string{
		generateSampleSecret("finicity", sampleAlphaNumeric20Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate finicity-client-secret")
		}
	}
	return &r
}

func FinicityAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity API token",
		RuleID:      "finicity-api-token",
		Regex:       generateSemiGenericRegex([]string{"finicity"}, hex32),
		SecretGroup: 1,
		Keywords:    []string{"finicity"},
	}

	// validate
	tps := []string{
		generateSampleSecret("finicity", sampleHex32Token),
	}
	return validate(r, tps)
}
