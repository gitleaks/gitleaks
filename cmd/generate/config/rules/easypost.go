package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func EasyPost() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "easypost-api-token",
		Description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
		Regex:       regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}`),
		Entropy:     2,
		Keywords:    []string{"EZAK"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("EZAK", "EZAK"+secrets.NewSecret(utils.AlphaNumeric("54"))),
	}
	return utils.Validate(r, tps, nil)
}

func EasyPostTestAPI() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "easypost-test-api-token",
		Description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
		Regex:       regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}`),
		Entropy:     2,
		Keywords:    []string{"EZTK"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("EZTK", "EZTK"+secrets.NewSecret(utils.AlphaNumeric("54"))),
	}
	return utils.Validate(r, tps, nil)
}
