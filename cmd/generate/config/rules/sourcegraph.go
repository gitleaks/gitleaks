package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SourceGraph() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "sourcegraph-access-token",
		Description: "Sourcegraph is a code search and navigation engine.",
		Regex:       utils.GenerateUniqueTokenRegex(`\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b`, true),
		Entropy:     3,
		Keywords:    []string{"sgp_", "sourcegraph"},
	}

	// validate
	tps := []string{
		`sgp_AaD80dc6E02eCAE1_d3cba16CC0F18fA14A2EFB61CbDFceEBf9fAD16b`,
		`sourcegraph: 6d2FabeB6ADd229Bc199FabA28fD3efb57dF0bD3`,
		`sgp_0D697F54cb24238EefB29af05Abf1b505E90950F`,
		`sgp_local_d7dfFD43cF2503B1da673EB560aAa3e80f16FA42`,
		`sgp_local_bcD1DA18de0d6476Be0f3BD7Ef9Da4f09b479aE5`,
	}
	fps := []string{
		`sgp_5555555dAAAAA7777777CcccCFaaaaaaaaaaaaaa`,                    // low entropy
		`sgp_local_d45b6G86aBb0F2Cee943902dbaDBCFCFDD1dA089`,              // invalid case
		`sgp_652d9a2e48FC7E!FcDbEA1BC2E2A6CE23cFe7F7D`,                    // invalid character
		`sgp_78Ad84a5B6e8A2fE5B_4085FB0ccaDDd29DB66Fd7FE9bA2C1cdCE8400CD`, // invalid length
		`BcAeb6640ad7DAD46AD73687946Ce85047d5C9Bb`,
	}
	return utils.Validate(r, tps, fps)
}
