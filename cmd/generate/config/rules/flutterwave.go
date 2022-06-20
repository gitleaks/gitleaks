package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
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
		generateSampleSecret("flutterwavePubKey", "FLWPUBK_TEST-"+secrets.NewSecret(hex("32"))+"-X"),
	}
	return validate(r, tps, nil)
}

func FlutterwaveSecretKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Flutterwave Secret Key",
		RuleID:      "flutterwave-secret-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{32}-X`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		generateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(hex("32"))+"-X"),
	}
	return validate(r, tps, nil)
}

func FlutterwaveEncKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Flutterwave Encryption Key",
		RuleID:      "flutterwave-encryption-key",
		Regex:       regexp.MustCompile(`FLWSECK_TEST-(?i)[a-h0-9]{12}`),
		Keywords:    []string{"FLWSECK_TEST"},
	}

	// validate
	tps := []string{
		generateSampleSecret("flutterwavePubKey", "FLWSECK_TEST-"+secrets.NewSecret(hex("12"))),
	}
	return validate(r, tps, nil)
}
