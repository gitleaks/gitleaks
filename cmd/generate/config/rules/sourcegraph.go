package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// SourceGraph detects SourceGraph access tokens.
// Token formats:
// - sgp_{16_hex}_{40_hex} - Standard format
// - sgp_local_{40_hex} - Local identifier format  
// - sgp_{40_hex} - Legacy format
func SourceGraph() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sourcegraph-access-token",
		Description: "Detected a SourceGraph access token, which may compromise code search platform access and expose sensitive source code.",
		Regex:       regexp.MustCompile(`\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40})\b`),
		Entropy:     3,
		Keywords:    []string{"sgp_"},
	}

	// validate with realistic test cases
	// True positives: valid tokens that should be detected
	tps := []string{
		// Standard format: sgp_{16_hex}_{40_hex}
		`sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b`,
		// Multiline scenario from issue #1697 (environment function)
		`environment("TOKEN", "sgp_1a2b3c4d5e6f7890_AbC123DeF456789012345678901234567890AbCd")`,
		// Legacy format: sgp_{40_hex}
		`sgp_0D697F54cb24238EefB29af05Abf1b505E90950F`,
		// Local identifier format: sgp_local_{40_hex}
		`sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42`,
		`sgp_local_bcD1DA18de0d6476Be0f3BD7Ef9Da4f09b479aE5`,
		// In JSON/YAML context
		`{"token": "sgp_1A2B3C4D5E6F7890_abcdef1234567890abcdef1234567890abcdef12"}`,
	}

	// False positives: patterns that should NOT trigger detection
	fps := []string{
		// Low entropy - repetitive patterns
		`sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa`,
		// Invalid character (G is not hex)
		`sgp_local_d45b6G86aBb0F2Cee943902dbaDBCFCFDD1dA089`,
		// Invalid character (! is not hex)
		`sgp_652d9a2e48FC7E!FcDbEA1BC2E2A6CE23cFe7F7D`,
		// Invalid length - too long for standard format
		`sgp_78Ad84a5B6e8A2fE5B_4085FB0ccaDDd29DB66Fd7FE9bA2C1cdCE8400CD`,
		// Just a hex string without sgp_ prefix
		`BcAeb6640ad7DAD46AD73687946Ce85047d5C9Bb`,
		// Placeholder patterns
		`sgp_0000000000000000_0000000000000000000000000000000000000000`,
		`sgp_xxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}

	return utils.Validate(r, tps, fps)
}
