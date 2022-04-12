package rules

import (
	"regexp"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

func FlutterwavePublicKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity Public Key",
		RuleID:      "flutterwave-public-key",
		Regex:       regexp.MustCompile(`FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWPUBK_TEST"},
	}

	// validate
	tps := []string{
		generateSampleSecret("flutterwavePubKey", "FLWPUBK_TEST-"+sampleHex32Token+"-X"),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate flutterwave-public-key")
		}
	}
	return &r
}

func FlutterwaveSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity Secret Key",
		RuleID:      "flutterwave-public-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		generateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+sampleHex32Token+"-X"),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate flutterwave-secret-key")
		}
	}
	return &r
}

func FlutterwaveEncKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Finicity Secret Key",
		RuleID:      "flutterwave-public-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		generateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+sampleHex12Token),
	}
	d := detect.NewDetector(config.Config{
		Rules: []*config.Rule{&r},
	})
	for _, tp := range tps {
		if len(d.DetectString(tp)) != 1 {
			log.Fatal().Msg("Failed to validate flutterwave-enc-key")
		}
	}
	return &r
}
