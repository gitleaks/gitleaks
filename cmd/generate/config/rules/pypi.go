package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func PyPiUploadToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
		RuleID:      "pypi-upload-token",
		Regex:       regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`),
		Entropy:     3,
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("pypi", "pypi-AgEIcHlwaS5vcmc"+secrets.NewSecret(utils.Hex("32"))+secrets.NewSecret(utils.Hex("32")))
	return utils.Validate(r, tps, nil)
}
