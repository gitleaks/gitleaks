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
		// Two shapes for Sourcegraph access tokens:
		//   1. sgp_-prefixed tokens are unique enough to match on their own.
		//   2. Legacy bare 40-char hex tokens require a "sourcegraph" identifier
		//      in proximity — otherwise they collide with git SHAs (#1898).
		Regex: utils.MergeRegexps(
			utils.GenerateUniqueTokenRegex(`sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}`, true),
			utils.GenerateSemiGenericRegex([]string{"sourcegraph"}, `[a-fA-F0-9]{40}`, true),
		),
		Entropy:  3,
		Keywords: []string{"sgp_", "sourcegraph"},
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
		// Git SHAs without a sourcegraph context should not match (#1898).
		`commit 6d2fabeb6add229bc199faba28fd3efb57df0bd3`,
		`See git log: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0`,
	}
	return utils.Validate(r, tps, fps)
}
