package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AnthropicApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-api-key",
		Description: "Identified an Anthropic API Key, which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`, false),
		Keywords: []string{
			"sk-ant-api03",
		},
	}

	// validate
	tps := []string{
		// Valid API key example
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
		// Generate additional random test keys
		utils.GenerateSampleSecret("anthropic", "sk-ant-api03-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("93"))+"AA"),
	}

	fps := []string{
		// Too short key (missing characters)
		"sk-ant-api03-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA",
		// Wrong suffix
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB",
		// Wrong prefix (admin key, not API key)
		"sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
	}

	return utils.Validate(r, tps, fps)
}

func AnthropicAdminApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-admin-api-key",
		Description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, false),
		Keywords: []string{
			"sk-ant-admin01",
		},
	}

	// validate
	tps := []string{
		// Valid admin key example
		"sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA",
		// Generate additional random test keys
		utils.GenerateSampleSecret("anthropic", "sk-ant-admin01-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("93"))+"AA"),
	}

	fps := []string{
		// Too short key (missing characters)
		"sk-ant-admin01-abc123xyz-456de-klMnopqrstuvwx-3456yza789bcde-1234fghijklmnopAA",
		// Wrong suffix
		"sk-ant-admin01-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzBB",
		// Wrong prefix (API key, not admin key)
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
	}

	return utils.Validate(r, tps, fps)
}

func AnthropicOAuthToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-oauth-token",
		Description: "Found an Anthropic OAuth access token (sk-ant-oat01-), which is tied to a Claude.ai Pro/Max subscription and can be used to act on the account's behalf.",
		// The sk-ant-oat01- prefix is highly specific, so anchor on it. Anthropic
		// does not publish a fixed length for OAuth tokens, so use a conservative
		// minimum rather than the {93}AA shape used by the api03/admin01 keys.
		Regex: utils.GenerateUniqueTokenRegex(`sk-ant-oat01-[a-zA-Z0-9_\-]{40,}`, false),
		Keywords: []string{
			"sk-ant-oat01",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("anthropic", "sk-ant-oat01-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("100")))

	fps := []string{
		// Too short to be a real OAuth token
		`anthropic_token = "sk-ant-oat01-tooShort"`,
	}

	return utils.Validate(r, tps, fps)
}

func AnthropicOAuthRefreshToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-oauth-refresh-token",
		Description: "Uncovered an Anthropic OAuth refresh token (sk-ant-ort01-), which can mint new access tokens and allow prolonged unauthorized access to a Claude.ai account.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-ant-ort01-[a-zA-Z0-9_\-]{40,}`, false),
		Keywords: []string{
			"sk-ant-ort01",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("anthropic", "sk-ant-ort01-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("100")))

	fps := []string{
		// Too short to be a real OAuth refresh token
		`anthropic_token = "sk-ant-ort01-tooShort"`,
	}

	return utils.Validate(r, tps, fps)
}
