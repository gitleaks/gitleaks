package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// SourceGraph detects SourceGraph access tokens.
// Token format: sgp_ followed by underscore-separated hexadecimal segments
// Example: sgp_1234567890abcdef_fedcba0987654321
func SourceGraph() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sourcegraph-access-token",
		Description: "Detected a SourceGraph access token, which may compromise code search platform access and expose sensitive source code.",
		Regex:       utils.GenerateUniqueTokenRegex("sgp", false),
		Entropy:     3,
		Keywords:    []string{"sgp_"},
	}

	// validate with comprehensive test cases
	// Generate realistic tokens with proper entropy
	tps := []string{
		// Standard format: sgp_{hex}_{hex}
		utils.GenerateSampleSecret("sourcegraph", "sgp_"+secrets.NewSecret(utils.Hex("16"))+"_"+secrets.NewSecret(utils.Hex("16"))),
		// Multiline scenario from issue #1697
		`environment("CODY_INTEGRATION_TEST_TOKEN", "sgp_` + secrets.NewSecret(utils.Hex("16")) + `_` + secrets.NewSecret(utils.Hex("16")) + `")`,
		// With newline between comma and token (specific case from issue)
		"SOURCEGRAPH_TOKEN=sgp_" + secrets.NewSecret(utils.Hex("16")) + "_" + secrets.NewSecret(utils.Hex("16")) + "\n",
		// Legacy format: sgp_{40_hex_chars}
		utils.GenerateSampleSecret("sourcegraph", "sgp_"+secrets.NewSecret(utils.Hex("40"))),
		// Format with 'local' identifier
		utils.GenerateSampleSecret("sourcegraph", "sgp_local_"+secrets.NewSecret(utils.Hex("40"))),
	}

	// False positives: patterns that should NOT trigger detection
	fps := []string{
		// Low entropy - all same character
		"sgp_0000000000000000_0000000000000000",
		"sgp_xxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxx",
		// Placeholder/example patterns
		"sgp_YOUR_TOKEN_HERE_REPLACE_THIS_VALUE",
		"sgp_****************_****************",
		// Documentation examples
		"sgp_example_token_value_not_real_key",
		// Invalid characters (non-hex)
		"sgp_GHIJKLMNOPQRSTUV_WXYZ1234567890AB",
	}

	return utils.Validate(r, tps, fps)
}
