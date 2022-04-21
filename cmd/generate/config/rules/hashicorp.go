package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Hashicorp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "HashiCorp Terraform user/org API token",
		RuleID:      "hashicorp-tf-api-token",
		Regex:       regexp.MustCompile(`(?i)[a-z0-9]{14}\.atlasv1\.[a-z0-9\-_=]{60,70}`),
		Keywords:    []string{"atlasv1"},
	}

	// validate
	tps := []string{
		generateSampleSecret("hashicorpToken", secrets.NewSecret(hex("14"))+".atlasv1."+secrets.NewSecret(alphaNumericExtended("60,70"))),
	}
	return validate(r, tps, nil)
}
