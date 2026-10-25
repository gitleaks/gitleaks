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

func AnthropicOauthRefreshToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "anthropic-oauth-refresh-token",
		Description: "Identified an Anthropic OAuth refresh token (e.g. Claude Code), which can be exchanged for new access tokens and provides long-lived access to Anthropic APIs on behalf of a user.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-ant-ort01-[a-zA-Z0-9_\-]{95}`, false),
		Keywords: []string{
			"sk-ant-ort01",
		},
	}

	// validate
	tps := []string{
		// Valid OAuth refresh token example
		"sk-ant-ort01-ort01samplexyzABC0123456789-_ort01samplexyzABC0123456789-_ort01samplexyzABC0123456789-_ort01sam",
		// Generate additional random test tokens
		utils.GenerateSampleSecret("anthropic", "sk-ant-ort01-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("95"))),
	}

	fps := []string{
		// Too short token (missing characters)
		"sk-ant-ort01-tooShort0123456789-_abcXYZ",
		// Wrong prefix (access token, not refresh token)
		"sk-ant-oat01-oat01samplexyzABC0123456789-_oat01samplexyzABC0123456789-_oat01samplexyzABC0123456789-_oat01sam",
	}

	return utils.Validate(r, tps, fps)
}
