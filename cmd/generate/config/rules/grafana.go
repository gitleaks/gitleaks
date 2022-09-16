package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GrafanaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Grafana api key (or Grafana cloud api key)",
		RuleID:      "grafana-api-key",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`eyJrIjoi[A-Za-z0-9]{70,400}={0,2}`),
		Keywords:    []string{"eyJrIjoi"},
	}

	// validate
	tps := []string{
		generateSampleSecret("grafana-api-key",
			"eyJrIjoi"+
				secrets.NewSecret(alphaNumeric("70"))),
	}
	return validate(r, tps, nil)
}

func GrafanaCloudApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Grafana cloud api token",
		RuleID:      "grafana-cloud-api-token",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`glc_[A-Za-z0-9+/]{32,400}={0,2}`),
		Keywords:    []string{"glc_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("grafana-cloud-api-token",
			"glc_"+
				secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}

func GrafanaServiceAccountToken() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Grafana service account token",
		RuleID:      "grafana-service-account-token",
		SecretGroup: 1,
		Regex:       generateUniqueTokenRegex(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`),
		Keywords:    []string{"glsa_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("grafana-service-account-token",
			"glsa_"+
				secrets.NewSecret(alphaNumeric("32"))+
				"_"+
				secrets.NewSecret((hex("8")))),
	}
	return validate(r, tps, nil)
}
