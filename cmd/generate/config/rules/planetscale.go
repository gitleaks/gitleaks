package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlanetScalePassword() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-password",
		Description: "PlanetScale password",
		Regex:       generateUniqueTokenRegex(`pscale_pw_(?i)[a-z0-9=\-_\.]{43}`),
		SecretGroup: 1,
		Keywords: []string{
			"pscale_pw_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(alphaNumericExtended("43"))),
	}
	return validate(r, tps, nil)
}

func PlanetScaleToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-api-token",
		Description: "PlanetScale API token",
		Regex:       generateUniqueTokenRegex(`pscale_tkn_(?i)[a-z0-9=\-_\.]{43}`),
		SecretGroup: 1,
		Keywords: []string{
			"pscale_tkn_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(alphaNumericExtended("43"))),
	}
	return validate(r, tps, nil)
}
