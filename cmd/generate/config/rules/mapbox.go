package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MapBox() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
		RuleID:      "mapbox-api-token",
		Regex:       utils.GenerateSemiGenericRegex([]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`, true),

		Keywords: []string{"mapbox"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("mapbox", "pk."+secrets.NewSecret(utils.AlphaNumeric("60"))+"."+secrets.NewSecret(utils.AlphaNumeric("22")))
	return utils.Validate(r, tps, nil)
}
