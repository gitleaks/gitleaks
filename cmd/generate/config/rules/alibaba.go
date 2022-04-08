package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func AlibabaAccessKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba AccessKey ID",
		RuleID:      "alibaba-access-key-id",
		Regex:       regexp.MustCompile(`(LTAI)(?i)[a-z0-9]{20}`),
		Keywords:    []string{"LTAI"},
	}

	// validate
	tps := []string{
		"alibabaKey := \"LTAI" + sampleHex20Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate alibaba-access-key-id")
		}
	}
	return &r
}

// TODO
func AlibabaSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Alibaba Secret Key",
		RuleID:      "alibaba-secret-key",
		Regex: generateSemiGenericRegex([]string{"alibaba"},
			alphaNumeric30),
		SecretGroup: 1,
		Keywords:    []string{"alibaba"},
	}

	// validate
	tps := []string{
		"alibabaSecret Key:= \"" + sampleAlphaNumeric30Token + "\"",
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate alibaba-secret-key")
		}
	}
	return &r
}
