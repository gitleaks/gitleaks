package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SaladCloudAPIKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a SaladCloud API Key, risking unauthorized cloud resource access and data breaches.",
		RuleID:      "saladcloud-api-key",
		Regex:       utils.GenerateUniqueTokenRegex(`salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235}`, false),
		Keywords:    []string{"salad_cloud_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("saladcloud", "salad_cloud_org_"+secrets.NewSecret(utils.AlphaNumeric("49"))),
		utils.GenerateSampleSecret("saladcloud", "salad_cloud_user_"+secrets.NewSecret(utils.AlphaNumeric("49"))),
	}
	return utils.Validate(r, tps, nil)
}
