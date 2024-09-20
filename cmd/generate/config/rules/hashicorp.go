package rules

import (
	"fmt"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HashiCorpTerraform() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
		RuleID:      "hashicorp-tf-api-token",
		Regex:       regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`),
		Entropy:     3.5,
		Keywords:    []string{"atlasv1"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("hashicorpToken", secrets.NewSecret(utils.Hex("14"))+".atlasv1."+secrets.NewSecret(utils.AlphaNumericExtended("60,70"))),
		`#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`,
	}
	fps := []string{
		`token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func HashicorpField() *config.Rule {
	keywords := []string{"administrator_login_password", "password"}
	// define rule
	r := config.Rule{
		Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
		RuleID:      "hashicorp-tf-password",
		Regex:       utils.GenerateSemiGenericRegex(keywords, fmt.Sprintf(`"%s"`, utils.AlphaNumericExtended("8,20")), true),
		Keywords:    keywords,
		Path:        regexp.MustCompile(`(?i)\.(?:tf|hcl)$`),
	}

	tps := map[string]string{
		// Example from: https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server.html
		"file.tf": "administrator_login_password = " + `"thisIsDog11"`,
		// https://registry.terraform.io/providers/petoju/mysql/latest/docs
		"file.hcl": "password       = " + `"rootpasswd"`,
	}
	fps := map[string]string{
		"file.tf":      "administrator_login_password = var.db_password",
		"file.hcl":     `password = "${aws_db_instance.default.password}"`,
		"unrelated.js": "password       = " + `"rootpasswd"`,
	}

	return utils.ValidateWithPaths(r, tps, fps)
}
