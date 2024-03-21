package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// See: https://docs.chief.tools/accountchief/tokens

func ChiefToolsPat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Chief Tools Personal Access Token, potentially leading to unauthorized access and sensitive content exposure.",
		RuleID:      "chieftools-pat",
		Regex:       regexp.MustCompile(`ctp_[a-zA-Z0-9]{30,248}`),
		Keywords:    []string{"ctp_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("chieftools", "ctp_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}

func ChiefToolsAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Chief Tools Access Token, posing a risk of compromised Chief Tools account integrations and data leaks.",
		RuleID:      "chieftools-access-token",
		Regex:       regexp.MustCompile(`cto_[a-zA-Z0-9]{30,248}`),
		Keywords:    []string{"cto_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("chieftools", "cto_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}

func ChiefToolsRefreshToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Chief Tools Refresh Token, which could allow prolonged unauthorized access to Chief Tools services.",
		RuleID:      "chieftools-refresh-token",
		Regex:       regexp.MustCompile(`ctr_[a-zA-Z0-9]{30,248}`),
		Keywords:    []string{"ctr_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("chieftools", "ctr_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}
