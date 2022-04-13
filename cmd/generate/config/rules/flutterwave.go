package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
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
	return validate(r, tps)
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
	return validate(r, tps)
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
	return validate(r, tps)
}
