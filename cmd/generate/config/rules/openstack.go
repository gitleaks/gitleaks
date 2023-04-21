package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"regexp"
)

func OpenStackRCPassword() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "openstack_rc_password",
		Description: "OpenStack RC file password",
		Regex:       regexp.MustCompile(`export OS_PASSWORD=(.*)`),
		SecretGroup: 1,
		Keywords: []string{
			"os_password",
		},
	}

	// validate
	tps := []string{
		generateSampleSecret("OS_PASSWORD", "export OS_PASSWORD="+secrets.NewSecret(alphaNumeric("35"))),
	}
	return validate(r, tps, nil)
}
