package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GrafanaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
		RuleID:      "grafana-api-key",

		Regex:    utils.GenerateUniqueTokenRegex(`eyJrIjoi[A-Za-z0-9]{70,400}={0,2}`, true),
		Keywords: []string{"eyJrIjoi"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("grafana-api-key",
			"eyJrIjoi"+
				secrets.NewSecret(utils.AlphaNumeric("70"))),
	}
	return utils.Validate(r, tps, nil)
}

func GrafanaCloudApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
		RuleID:      "grafana-cloud-api-token",

		Regex:    utils.GenerateUniqueTokenRegex(`glc_[A-Za-z0-9+/]{32,400}={0,2}`, true),
		Keywords: []string{"glc_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("grafana-cloud-api-token",
			"glc_"+
				secrets.NewSecret(utils.AlphaNumeric("32"))),
	}
	return utils.Validate(r, tps, nil)
}

func GrafanaServiceAccountToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
		RuleID:      "grafana-service-account-token",

		Regex:    utils.GenerateUniqueTokenRegex(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`, true),
		Keywords: []string{"glsa_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("grafana-service-account-token",
			"glsa_"+
				secrets.NewSecret(utils.AlphaNumeric("32"))+
				"_"+
				secrets.NewSecret((utils.Hex("8")))),
	}
	return utils.Validate(r, tps, nil)
}
