package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PyPiUploadToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "PyPI upload token",
		RuleID:      "pypi-upload-token",
		Regex: regexp.MustCompile(
			`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
	}

	// validate
	tps := []string{"pypiToken := \"pypi-AgEIcHlwaS5vcmc" + secrets.NewSecret(hex("32")) +
		secrets.NewSecret(hex("32")) + "\""}
	return validate(r, tps, nil)
}
