package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Clojars() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "clojars-api-token",
		Description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
		Regex:       regexp.MustCompile(`(?i)CLOJARS_[a-z0-9]{60}`),
		Entropy:     2,
		Keywords:    []string{"clojars_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("clojars", "CLOJARS_"+secrets.NewSecret(utils.AlphaNumeric("60")))
	return utils.Validate(r, tps, nil)
}
