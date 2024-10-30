package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GrafanaApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "grafana-api-key",
		Description: "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
		Regex:       utils.GenerateUniqueTokenRegex(`eyJrIjoi[A-Za-z0-9]{70,400}={0,3}`, true),
		Entropy:     3,
		Keywords:    []string{"eyJrIjoi"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("grafana-api-key", "eyJrIjoi"+secrets.NewSecret(utils.AlphaNumeric("70")))
	return utils.Validate(r, tps, nil)
}

func GrafanaCloudApiToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "grafana-cloud-api-token",
		Description: "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
		Regex:       utils.GenerateUniqueTokenRegex(`glc_[A-Za-z0-9+/]{32,400}={0,3}`, true),
		Entropy:     3,
		Keywords:    []string{"glc_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("grafana-cloud-api-token", "glc_"+secrets.NewSecret(utils.AlphaNumeric("32")))
	tps = append(tps,
		utils.GenerateSampleSecret("grafana-cloud-api-token",
			"glc_"+
				secrets.NewSecret(utils.AlphaNumeric("32"))),
		`loki_key: glc_eyJvIjoiNzQ0NTg3IiwibiI7InN0YWlrLTQ3NTgzMC1obC13cml0ZS1oYW5kc29uJG9raSIsImsiOiI4M2w3cmdYUlBoMTUyMW1lMU023nl5UDUiLCJtIjp7IOIiOiJ1cyJ9fQ==`,
		// TODO:
		//`  loki:
		//endpoint: https://322137:glc_eyJvIjoiNzQ0NTg3IiwibiI7InN0YWlrLTQ3NTgzMC1obC13cml0ZS1oYW5kc29uJG9raSIsImsiOiI4M2w3cmdYUlBoMTUyMW1lMU023nl5UDUiLCJtIjp7IOIiOiJ1cyJ9fQ==@logs-prod4.grafana.net/loki/api/v1/push`,
	)
	fps := []string{
		// Low entropy.
		`glc_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		`   API_KEY="glc_111111111111111111111111111111111111111111="`,
		// Invalid.
		`static void GLC_CreateLightmapTextureArray(void);
static void GLC_CreateLightmapTexturesIndividual(void);

void GLC_UploadLightmap(int textureUnit, int lightmapnum);`,
		`// Alias models
void GLC_StateBeginUnderwaterAliasModelCaustics(texture_ref base_texture, texture_ref caustics_texture)
{`,
	}
	return utils.Validate(r, tps, fps)
}

func GrafanaServiceAccountToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "grafana-service-account-token",
		Description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
		Regex:       utils.GenerateUniqueTokenRegex(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`, true),
		Entropy:     3,
		Keywords:    []string{"glsa_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("grafana-service-account-token", "glsa_"+secrets.NewSecret(utils.AlphaNumeric("32"))+"_"+secrets.NewSecret(utils.Hex("8")))
	tps = append(tps,
		`'Authorization': 'Bearer glsa_pITqMOBIfNH2KL4PkXJqmTyQl0D9QGxF_486f63e1'`,
	)
	fps := []string{
		"glsa_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX_AAAAAAAA",
	}
	return utils.Validate(r, tps, fps)
}
