package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PlanetScalePassword() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-password",
		Description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_pw_(?i)[a-z0-9=\-_\.]{32,64}`, true),

		Keywords: []string{
			"pscale_pw_",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(utils.AlphaNumericExtended("32"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(utils.AlphaNumericExtended("43"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_pw_"+secrets.NewSecret(utils.AlphaNumericExtended("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func PlanetScaleAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-api-token",
		Description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_tkn_(?i)[a-z0-9=\-_\.]{32,64}`, true),

		Keywords: []string{
			"pscale_tkn_",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(utils.AlphaNumericExtended("32"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(utils.AlphaNumericExtended("43"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_tkn_"+secrets.NewSecret(utils.AlphaNumericExtended("64"))),
	}
	return utils.Validate(r, tps, nil)
}

func PlanetScaleOAuthToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "planetscale-oauth-token",
		Description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
		Regex:       utils.GenerateUniqueTokenRegex(`pscale_oauth_(?i)[a-z0-9=\-_\.]{32,64}`, true),

		Keywords: []string{
			"pscale_oauth_",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(utils.AlphaNumericExtended("32"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(utils.AlphaNumericExtended("43"))),
		utils.GenerateSampleSecret("planetScalePassword", "pscale_oauth_"+secrets.NewSecret(utils.AlphaNumericExtended("64"))),
	}
	return utils.Validate(r, tps, nil)
}
