package rules

import (
	"fmt"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Tailscale() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Detected a Tailscale key, potentially allowing unauthorized access to your Tailscale network and connected devices.",
		RuleID:      "tailscale-key",
		Regex:       regexp.MustCompile(`\btskey-(api|auth|client|scim|webhook)-[0-9A-Za-z_]+-[0-9A-Za-z_]+\b`),
		Keywords: []string{
			// https://tailscale.com/kb/1277/key-prefixes
			"tskey-api",     // API access token
			"tskey-auth",    // Pre-authentication key
			"tskey-client",  // Oauth client key
			"tskey-scim",    // SCIM key
			"tskey-webhook", // Webhook key
		},
	}

	// validate
	tps := []string{
		// API keys
		"tskey-api-abcDEF1CNTRL-091234567890ABCDEF",
		"My Tailscale API key is tskey-api-abcDEF1CNTRL-091234567890ABCDEF",
		"TAILSCALE_API_KEY=tskey-api-abcDEF1CNTRL-091234567890ABCDEF",
		secrets.NewSecret(fmt.Sprintf("tskey-api-%s-%s", utils.AlphaNumeric("12"), utils.AlphaNumeric("18"))),

		// Auth keys
		"tskey-auth-abcDEF1CNTRL-091234567890ABCDEF",
		"TAILSCALE_AUTH_KEY=tskey-auth-abcDEF1CNTRL-091234567890ABCDEF",
		secrets.NewSecret(fmt.Sprintf("tskey-auth-%s-%s", utils.AlphaNumeric("12"), utils.AlphaNumeric("18"))),

		// Client keys
		"tskey-client-abcDEF1CNTRL-091234567890ABCDEF",
		secrets.NewSecret(fmt.Sprintf("tskey-client-%s-%s", utils.AlphaNumeric("12"), utils.AlphaNumeric("18"))),

		// SCIM keys
		"tskey-scim-abcDEF1CNTRL-091234567890ABCDEF",
		secrets.NewSecret(fmt.Sprintf("tskey-scim-%s-%s", utils.AlphaNumeric("12"), utils.AlphaNumeric("18"))),

		// Webhook keys
		"tskey-webhook-abcDEF1CNTRL-091234567890ABCDEF",
		secrets.NewSecret(fmt.Sprintf("tskey-webhook-%s-%s", utils.AlphaNumeric("12"), utils.AlphaNumeric("18"))),
	}

	fps := []string{
		"tskay-api-abcDEF1CNTRL-091234567890ABCDEF",     // Wrong prefix
		"tskey-unknown-abcDEF1CNTRL-091234567890ABCDEF", // Unknown key type
	}

	return utils.Validate(r, tps, fps)
}
