package rules

import (
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Hashicorp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
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

func HashicorpField() *config.Rule {
	keywords := []string{"administrator_login_password", "password"}
	// define rule
	r := config.Rule{
		Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
		RuleID:      "hashicorp-tf-password",
		Regex:       generateSemiGenericRegex(keywords, fmt.Sprintf(`"%s"`, alphaNumericExtended("8,20")), true),
		Keywords:    keywords,
	}

	tps := []string{
		// Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
		"administrator_login_password = " + `"thisIsDog11"`,
		// https://registry.terraform.io/providers/petoju/mysql/latest/docs
		"password       = " + `"rootpasswd"`,
	}
	fps := []string{
		"administrator_login_password = var.db_password",
		`password = "${aws_db_instance.default.password}"`,
	}
	return validate(r, tps, fps)
}
