package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// MCPServerCredential detects credentials embedded in Model Context
// Protocol (MCP) server configuration files. Claude Desktop, Claude Code,
// and other MCP-compatible clients store per-server environment variables
// in JSON files such as claude_desktop_config.json or .mcp.json. These
// env blocks routinely hold long-lived secrets (Linear, GitHub, Slack,
// PostgreSQL, custom MCP_SERVER_TOKEN values) that ship to disk in plain
// text and frequently get committed by mistake.
//
// The rule is scoped by Path to those config files, then looks for
// env-style keys ending in TOKEN, KEY, SECRET, PASSWORD, PASSWD, PAT,
// or BEARER inside an "env" object, with a non-trivial value.
//
// Path scoping keeps false positives low: the same regex would be too
// noisy across a whole repo, but inside MCP config files an env value
// of this shape is almost always a real credential.
func MCPServerCredential() *config.Rule {
	r := config.Rule{
		RuleID:      "mcp-server-credential",
		Description: "Detected a credential inside an MCP server configuration file (claude_desktop_config.json or .mcp.json), risking exposure of integrated service tokens such as Linear, GitHub, Slack, or custom MCP server keys.",
		// Match a JSON key whose name ends with TOKEN, KEY, SECRET, PASSWORD,
		// PASSWD, PAT, or BEARER, paired with a non-empty quoted value of
		// at least 16 characters. The value capture excludes obvious
		// placeholders (`<...>`, `${...}`, `xxx...`) via the allowlist.
		//language=regexp
		Regex: regexp.MustCompile(`(?i)"[A-Z0-9_]*(?:TOKEN|API[_-]?KEY|SECRET|PASSWORD|PASSWD|PAT|BEARER)"\s*:\s*"([^"\s$<{][^"]{15,})"`),
		Path:  regexp.MustCompile(`(?i)(?:claude_desktop_config\.json|\.?mcp\.json)$`),
		Keywords: []string{
			"token",
			"key",
			"secret",
			"password",
			"bearer",
			"pat",
		},
		Entropy: 3.5,
		Allowlists: []*config.Allowlist{
			{
				// Skip obvious placeholders / env-var indirections / common
				// dummy strings that pass the entropy floor.
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)\b(?:your|example|placeholder|changeme|todo|fixme|xxx+|ABC+|REPLACE_ME|YOUR_TOKEN|YOUR_KEY|REDACTED|dummy|sample|test|mock|fake|lorem|insert)\b`),
					regexp.MustCompile(`^\$\{[^}]+\}$`),
					regexp.MustCompile(`^<[^>]+>$`),
				},
			},
		},
	}

	// True positives keyed by file path.
	tps := map[string]string{
		"claude_desktop_config.json": `{
  "mcpServers": {
    "linear": {
      "command": "npx",
      "args": ["-y", "@linear/mcp-server"],
      "env": {
        "LINEAR_API_KEY": "lin_api_aW5DAFiyMK53ad1fLJpQz9hT8sbVx2RcEoHN"
      }
    }
  }
}`,
		".mcp.json": `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_` + secrets.NewSecret(utils.AlphaNumeric("36")) + `"
      }
    }
  }
}`,
		"mcp.json": `{
  "mcpServers": {
    "custom": {
      "command": "node",
      "args": ["./server.js"],
      "env": {
        "MCP_SERVER_TOKEN": "sktok_R7kQp2vN4bH9wL3mZ8xY1jF6cT5dG0sA"
      }
    }
  }
}`,
	}

	// False positives.
	fps := map[string]string{
		// Wrong filename: same content in any other JSON should not match.
		"package.json": `{"mcpServers":{"linear":{"env":{"LINEAR_API_KEY":"lin_api_aW5DAFiyMK53ad1fLJpQz9hT8sbVx2RcEoHN"}}}}`,
		// Placeholder values.
		"claude_desktop_config_placeholder.json": `{
  "mcpServers": {
    "linear": {
      "env": {
        "LINEAR_API_KEY": "YOUR_LINEAR_API_KEY_HERE"
      }
    }
  }
}`,
		// Env var indirection.
		"claude_desktop_config_envvar.json": `{
  "mcpServers": {
    "linear": {
      "env": {
        "LINEAR_API_KEY": "${LINEAR_API_KEY}"
      }
    }
  }
}`,
		// Angle-bracket placeholder.
		"claude_desktop_config_angle.json": `{
  "mcpServers": {
    "linear": {
      "env": {
        "LINEAR_API_KEY": "<your-linear-key>"
      }
    }
  }
}`,
		// Value too short.
		"claude_desktop_config_short.json": `{
  "mcpServers": {
    "x": { "env": { "API_KEY": "abc" } }
  }
}`,
	}

	// Note on filename matching: the path regex is anchored with `$`, so
	// `package.json` does not satisfy it and the keyword pre-filter alone
	// can never produce a finding outside MCP config files.
	return utils.ValidateWithPaths(r, tps, fps)
}
