package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PrivateKeyNonPEMFormat() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Private Key Non PEM Format",
		RuleID:      "private-key-non-pem-format",
		Regex:       regexp.MustCompile(`(?i)MII[BCEJ]`),
		Keywords:    []string{"MII"},
	}

	// validate
	tps := []string{`MIIEOgIBAAJ...`,
	} // gitleaks:allow
	return validate(r, tps, nil)
}
