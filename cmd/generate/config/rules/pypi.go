package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PyPiUploadToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
		RuleID:      "pypi-upload-token",
		Regex: regexp.MustCompile(
			`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}`),
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
	}

	// validate
	tps := []string{"pypiToken := \"pypi-AgEIcHlwaS5vcmc" + secrets.NewSecret(utils.Hex("32")) +
		secrets.NewSecret(utils.Hex("32")) + "\""}
	return utils.Validate(r, tps, nil)
}
