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
		Regex:       generateUniqueTokenRegex(`pscale_pw_(?i)[a-z0-9=\-_\.]{32,64}`),
		SecretGroup: 1,
		Keywords: []string{
			"pscale_pw_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(alphaNumericExtended("32"))),
		generateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(alphaNumericExtended("43"))),
		generateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(alphaNumericExtended("64"))),
	}
	return validate(r, tps, nil)
}

func PlanetScaleAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-api-token",
		Description: "PlanetScale API token",
		Regex:       generateUniqueTokenRegex(`pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64}`),
		SecretGroup: 1,
		Keywords: []string{
			"pscale_tkn_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(alphaNumericExtended("32"))),
		generateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(alphaNumericExtended("43"))),
		generateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(alphaNumericExtended("64"))),
	}
	return validate(r, tps, nil)
}

func PlanetScaleOAuthToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-oauth-token",
		Description: "PlanetScale OAuth token",
		Regex:       generateUniqueTokenRegex(`pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64}`),
		SecretGroup: 1,
		Keywords: []string{
			"pscale_oauth_",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(alphaNumericExtended("32"))),
		generateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(alphaNumericExtended("43"))),
		generateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(alphaNumericExtended("64"))),
	}
	return validate(r, tps, nil)
}
