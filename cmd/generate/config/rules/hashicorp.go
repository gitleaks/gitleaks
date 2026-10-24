package rules

import (
	"fmt"
	"strings"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func HashiCorpTerraform() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "hashicorp-tf-api-token",
		Description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
		Regex:       regexp.MustCompile(`(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`),
		Entropy:     3.5,
		Keywords:    []string{"atlasv1"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("hashicorpToken", secrets.NewSecret(utils.Hex("14"))+".atlasv1."+secrets.NewSecret(utils.AlphaNumericExtended("60,70")))
	tps = append(tps,
		`#token = "hE1hlYILrSqpqh.atlasv1.ARjZuyzl33F71WR55s6ln5GQ1HWIwTDDH3MiRjz7OnpCfaCb1RCF5zGaSncCWmJdcYA"`,
	)
	fps := []string{
		`token        = "xxxxxxxxxxxxxx.atlasv1.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"`, // low entropy
	}
	return utils.Validate(r, tps, fps)
}

func HashicorpField() *config.Rule {
	keywords := []string{"administrator_login_password", "password"}
	// define rule
	// The identifier must *end* with the keyword and be followed only by whitespace before the
	// operator. GenerateSemiGenericRegex allows word characters in between, which matches
	// unrelated attributes such as `password_policy = "excellent"` and prose in comments.
	r := config.Rule{
		RuleID:      "hashicorp-tf-password",
		Description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
		Regex: regexp.MustCompile(
			fmt.Sprintf(`(?i)[\w.-]{0,50}?(?:%s)[ \t]{0,20}(?:=|:{1,3}=|=>|\?=|:)[ \t]{0,5}("%s")`,
				strings.Join(keywords, "|"), utils.AlphaNumericExtended("8,20")),
		),
		Entropy:  2,
		Path:     regexp.MustCompile(`(?i)\.(?:tf|hcl)$`),
		Keywords: keywords,
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
		// https://github.com/gitleaks/gitleaks/issues/1832 - a different attribute that merely starts with the keyword
		"policy.tf": `password_policy = "excellent"`,
		// ... and prose in a comment that happens to mention a password
		"comment.tf": `# Create secrets containing the database password, enabling "automatic rotation"`,
	}

	return utils.ValidateWithPaths(r, tps, fps)
}
