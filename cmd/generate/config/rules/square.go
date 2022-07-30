package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SquareAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-access-token",
		Description: "Square Access Token",
		Regex:       generateUniqueTokenRegex(`sq0atp-[0-9A-Za-z\-_]{22}`),
		Keywords:    []string{"sq0atp-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("square", secrets.NewSecret(`sq0atp-[0-9A-Za-z\-_]{22}`)),
	}
	return validate(r, tps, nil)
}

func SquareSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "square-secret",
		Description: "Square Secret",
		Regex:       generateUniqueTokenRegex(`sq0csp-[0-9A-Za-z\\-_]{43}`),
		Keywords:    []string{"sq0csp-"},
	}

	// validate
	tps := []string{
		generateSampleSecret("square", secrets.NewSecret(`sq0csp-[0-9A-Za-z\\-_]{43}`)),
	}
	return validate(r, tps, nil)
}
