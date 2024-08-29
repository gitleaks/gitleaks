package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		RuleID:      "clojars-api-token",
		Regex:       regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`),
		Keywords:    []string{"clojars"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("clojars", "CLOJARS_"+secrets.NewSecret(utils.AlphaNumeric("60"))),
	}
	return utils.Validate(r, tps, nil)
}
