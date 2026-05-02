package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func ClaudeCodeSessionURL() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a Claude Code session URL, which could allow unauthorized remote-control access to an active Claude Code session if leaked.",
		RuleID:      "claude-code-session-url",
		Regex:       regexp.MustCompile(`(?i)\bhttps?://claude\.ai/code/session_[A-Za-z0-9]{16,}\b`),
		Keywords:    []string{"claude.ai/code/session_"},
	}

	// validate
	tps := []string{
		"https://claude.ai/code/session_01DDpXdCk8uhiRdzku123456",
		"http://claude.ai/code/session_01DDpXdCk8uhiRdzku123456",
		"see https://claude.ai/code/session_01DDpXdCk8uhiRdzku123456 for context",
		`session = "https://claude.ai/code/session_01DDpXdCk8uhiRdzku123456"`,
		"https://CLAUDE.AI/code/session_01DDpXdCk8uhiRdzku123456",
		"https://claude.ai/code/session_01DDpXdCk8uhiRdzku123456/",
		"https://claude.ai/code/session_01DDpXdCk8uhiRdzku123456?ref=foo",
		"https://claude.ai/code/session_" + secrets.NewSecret(`[A-Za-z0-9]{24}`),
	}
	fps := []string{
		// Wrong host
		"https://example.com/code/session_01DDpXdCk8uhiRdzku123456",
		// Wrong path prefix
		"https://claude.ai/chat/session_01DDpXdCk8uhiRdzku123456",
		// Missing session_ prefix
		"https://claude.ai/code/01DDpXdCk8uhiRdzku123456",
		// ID too short to be plausible
		"https://claude.ai/code/session_short",
	}
	return utils.Validate(r, tps, fps)
}
