package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func Nuget() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Nuget Password",
		RuleID:      "nuget-config-password",
		Regex:       regexp.MustCompile(`(?i)(<add key=\"(ClearTextPassword)|(Password)\"\s*)(value=\"[A-Za-z0-9]+\"\s*/>)`),
		SecretGroup: 2,
		Keywords:    []string{"cleartextpassword", "password"},
	}

	// validate
	tps := []string{
		`<add key="ClearTextPassword" value="nvnmsklavkoneroijvoks894789532ifjklwnfi28ur" />`,
	}
	fps := []string{
		`<add key="ClearTextPassword" value="%Password%" />`,
	}
	return validate(r, tps, fps)
}
