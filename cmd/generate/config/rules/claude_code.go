package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// ClaudeCodeOAuthToken detects Anthropic Claude Code OAuth tokens issued
// by `claude setup-token`. These tokens authenticate Pro / Max / Team /
// Enterprise subscribers from CI pipelines, GitHub Actions, and IDE
// integrations. They are stored on disk at ~/.claude/.credentials.json
// and are commonly exported as the CLAUDE_CODE_OAUTH_TOKEN env var.
//
// Format: sk-ant-oat01-<95 chars from [A-Za-z0-9_-]>
// Total token length is 108 characters. Length is observed against
// production tokens; if Anthropic rotates the format, widen the body
// quantifier to {80,120} or similar.
//
// This is distinct from the Anthropic API key (sk-ant-api03-) and the
// Anthropic Admin API key (sk-ant-admin01-) already covered by separate
// rules in this package.
func ClaudeCodeOAuthToken() *config.Rule {
	r := config.Rule{
		RuleID:      "claude-code-oauth-token",
		Description: "Detected an Anthropic Claude Code OAuth token, which grants subscription-based access to Claude Code and may expose private code, prompts, and account usage if leaked.",
		Regex:       utils.GenerateUniqueTokenRegex(`sk-ant-oat01-[a-zA-Z0-9_\-]{95}`, false),
		Keywords: []string{
			"sk-ant-oat01",
		},
	}

	tps := []string{
		// Synthetic 108-char token (prefix + 95 body chars).
		"sk-ant-oat01-abc123xyz_456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzZQ",
		// Generated random fixture.
		utils.GenerateSampleSecret("claude-code", "sk-ant-oat01-"+secrets.NewSecret(utils.AlphaNumericExtendedShort("95"))),
		// CLAUDE_CODE_OAUTH_TOKEN env-var form.
		`CLAUDE_CODE_OAUTH_TOKEN="sk-ant-oat01-` + secrets.NewSecret(utils.AlphaNumericExtendedShort("95")) + `"`,
	}

	fps := []string{
		// Too short (92 body chars).
		"sk-ant-oat01-abc123xyz_456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xy",
		// Wrong prefix (API key, covered by anthropic-api-key rule).
		"sk-ant-api03-abc123xyz-456def789ghij-klmnopqrstuvwx-3456yza789bcde-1234fghijklmnopby56aaaogaopaaaabc123xyzAA",
		// Wrong prefix (admin key, covered by anthropic-admin-api-key rule).
		"sk-ant-admin01-abc12fake-456def789ghij-klmnopqrstuvwx-3456yza789bcde-12fakehijklmnopby56aaaogaopaaaabc123xyzAA",
	}

	return utils.Validate(r, tps, fps)
}
