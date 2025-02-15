package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Sonar() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
		RuleID:      "sonar-api-token",
		Regex: utils.GenerateSemiGenericRegex([]string{"sonar[_.-]?login"},utils.AlphaNumeric("40"), true), 
		Keywords: []string{"sonar"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("sonar", "12345678ABCDEFH1234567890ABCDEFH12345678")
	tps = append(tps,
		`const SONAR_LOGIN = "12345678ABCDEFH1234567890ABCDEFH12345678"`, // gitleaks:allow
		`const SONAR_LOGIN = "sqp_12345678ABCDEFH1234567890ABCDEFH12345678"`,   // gitleaks:allow
		`SONAR_LOGIN := "12345678ABCDEFH1234567890ABCDEFH12345678"`,      // gitleaks:allow
		`SONAR.LOGIN ::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,     // gitleaks:allow
		`SONAR.LOGIN :::= "12345678ABCDEFH1234567890ABCDEFH12345678"`,    // gitleaks:allow
		`SONAR.LOGIN ?= "12345678ABCDEFH1234567890ABCDEFH12345678"`,    // gitleaks:allow
		`name="sonar.login" value="12345678ABCDEFH1234567890ABCDEFH12345678"`,   // gitleaks:allow
		`name="sonar.login" value="sqp_12345678ABCDEFH1234567890ABCDEFH12345678"`,   // gitleaks:allow
	)
	return utils.Validate(r, tps, nil)
}
