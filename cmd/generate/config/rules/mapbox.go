package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MapBox() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "MapBox API token",
		RuleID:      "mapbox-api-token",
		Regex:       generateSemiGenericRegex([]string{"mapbox"}, `pk\.[a-z0-9]{60}\.[a-z0-9]{22}`),
		SecretGroup: 1,
		Keywords:    []string{"mapbox"},
	}

	// validate
	tps := []string{
		generateSampleSecret("mapbox", "pk."+secrets.NewSecret(alphaNumeric("60"))+"."+secrets.NewSecret(alphaNumeric("22"))),
	}
	return validate(r, tps, nil)
}
