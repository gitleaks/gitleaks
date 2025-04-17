package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// https://developer.1password.com/docs/service-accounts/security/?token-example=encoded
func OnePasswordServiceAccountToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "1password-service-account-token",
		Description: "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.",
		Regex:       regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`),
		Entropy:     4,
		Keywords:    []string{"ops_"},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("1password", secrets.NewSecret(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`)),
		`### 1Password System Vault Name
export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoibXkuMXBhc3N3b3JkLmNvbSIsInVzZXJBdXRoIjp7Im1ldGhvZCI6IlNSUGctNDA5NiIsImFsZyI6IlBCRVMyZy1IUzI1NiIsIml0ZXJhdGlvbnMiOjY1MdAwMCwic2FsdCI6InE2dE0tYzNtRDhiNUp2OHh1YVzsUmcifSwiZW1haWwiOiJ5Z3hmcm0zb21oY3NtQDFwYXNzd29yZHNlcnZpY2VhY2NvdW50cy5jb20iLCJzcnBYIjoiM2E5NDdhZmZhMDQ5NTAxZjkxYzk5MGFiY2JiYWRlZjFjMjM5Y2Q3YTMxYmI1MmQyZjUzOTA2Y2UxOTA1OTYwYiIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiVVpleERsLVgyUWxpa0VqRjVUUjRoODhOd29ZcHRqSHptQmFTdlNrWGZmZyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtNDZGUUVNLUVZS1hTQS1NUU0yUy04U0JSUS01QjZGUC1HS1k2ViIsInRocm90dGxlU2VjcmV0Ijp7InNlZWQiOiJjZmU2ZTU0NGUxZTlmY2NmZjJlYjBhYWZmYTEzNjZlMmE2ZmUwZDVlZGI2ZTUzOTVkZTljZmY0NDY3NDUxOGUxIiwidXVpZCI6IjNVMjRMNVdCNkpFQ0pEQlhJNFZOSTRCUzNRIn0sImRldmljZVV1aWQiOiJqaGVlY3F4cm41YTV6ZzRpMnlkbjRqd3U3dSJ9
`,
		`PYTEST_SVC_ACCT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoiemFjaC1hbmQtbGVhbm5lLjFwYXNzd29yZC5jb20iLCJ1c2VyQXV0aCI6eyJtZXRob2QiOiJTUlBnLTQwOTYiLCJhbGciOiJQQkVLMmctSFMyNTYiLCJpdGVyYXRpb25zIjo2NTAwMDAsInNhbHQiOiJlYUZRQmNVemJyTHhnM2d4bHFQLVVBIn0sImVtYWlsIjoiMm9iNGRpeDdiNTdrYUAxcGFzc3dvcmRzZXJ2aWNlYWNjb3VudHMuY29tIiwic3JwWCI6ImVmZDY4YjNhZTkwMmRjZjRiMzEzYjE5MjYwZmY0OGUzMjU2ZDlhOGNkM2JmMmY3YzI2YzU1ZWJkNjZlZGU4NWEiLCJtdWsiOnsiYWxnIjoiQTI1NkdDTSIsImV4dCI6dHJ1ZSwiayI6IlMwaGE0SDhqbEhRblJCWmxvYnBmR1BneERmbS1pRGNkZWY0bFdYU0VSbmMiLCJrZXlfb3BzIjpbImRlY3J5cHQiLCJlbmNyeXB0Il0sImt0eSI6Im9jdCIsImtpZCI6Im1wIn0sInNlY3JldEtleSI6IkEzLUdHOUVRNi1LUzQ0QVctQU5QVkYtUkdQTDktQlNKUTMtR1NHR0giLCJ0aHJvdHRsZVNlY3JldCI6eyJzZWVkIjoiN2I0OTMxMmJiOTlkZTFiNjU5ODZkYzIzOWU4YWNmZWMxMTU0M2E2OGQxYmYwMjZmZTgzMjg3NWYxNmJlOWY2NiIsInV1aWQiOiJDV1RHQ0hMNlNWRkdSTlg0SzNENUJVSDZDSSJ9LCJkZXZpY2VVdWlkIjoiMnFld3JpaGtqbmt1Zmh6ZGdmZ2hnNmM1cGUifQ`,
		`    "sourceContent": "ops_eyJlbWFpbCI6ImVqd2U2NHFtbHhocmlAMXBhc3N3b3Jkc2VydmljZWFjY291bnRzLmxjbCIsIm11ayI6eyJhbGciOiJBMjU2R0NNIiwiZXh0Ijp0cnVlLCJrIjoiTThWUGZJYzhWRWZUaGNNWExhS0NLRjhzTWg1Sk1ac1BBdHU5MmZRTmItbyIsImtleV9vcHMiOlsiZW5jcnlwdCIsImRlY3J5cHQiXSwia3R5Ijoib2N0Iiwia2lkIjoibXAifSwic2VjcmV0S2V5IjoiQTMtQzRaSk1OLVBRVFpUTC1IR0w4NC1HNjRNNy1LVlpSTi00WlZQNiIsInNycFgiOiI4NzBkNjdhOWU2MjY2MjVkOWUzNjg1MDc4MDRjOWMzMmU2NjFjNTdlN2U1NTg3NzgyOTFiZjI5ZDVhMjc5YWUxIiwic2lnbkluQWRkcmVzcyI6ImdvdGhhbS5iNWxvY2FsLmNvbTo0MDAwIiwidXNlckF1dGgiOnsibWV0aG9kIjoiU1JQZy00MDk2IiwiYWxnIjoiUEJFUzJnLUhTMjU2IiwiaXRlcmF0aW9ucyI6MTAwMDAwLCJzYWx0IjoiRk1SVVBpeXJONFhmXzhIb2g2WVJYUSJ9fQ\n\nops_token is secret.\n",`,
	}
	fps := []string{
		// Invalid
		`        login:
          serviceAccountToken:
            fn::secret: ops_eyJzaWduSW5B..[Redacted]`,
		`: To start using this service account, run the following command:
:
: export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoiaHR0cHM6...`,
		// Low entropy.
		`ops_eyJxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

// Reference:
// - https://1passwordstatic.com/files/security/1password-white-paper.pdf
func OnePasswordSecretKey() *config.Rule {
	// 1Password secret keys include several hyphens but these are only for readability
	// and are stripped during 1Password login. This means that the following are technically
	// the same valid key:
	//   - A3ASWWYB798JRYLJVD423DC286TVMH43EB
	//   - A-3-A-S-W-W-Y-B-7-9-8-J-R-Y-L-J-V-D-4-2-3-D-C-2-8-6-T-V-M-H-4-3-E-B
	// But in practice, when these keys are added to a vault, exported in an emergency kit, or
	// copied, they have hyphens that follow one of two patterns I can find:
	//   - A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB (every key I've generated has this pattern)
	//   - A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB  (the whitepaper includes this example, which could just be a typo)
	// To avoid a complicated regex that checks for every possible situation it's probably best
	// to scan for the these two patterns.
	r := config.Rule{
		Description: "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
		RuleID:      "1password-secret-key",
		Regex:       regexp.MustCompile(`\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`),
		Entropy:     3.8,
		Keywords:    []string{"A3-"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("1password", secrets.NewSecret(`A3-[A-Z0-9]{6}-[A-Z0-9]{11}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`))
	tps = append(tps, utils.GenerateSampleSecrets("1password", secrets.NewSecret(`A3-[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}`))...)
	tps = append(tps,
		// from whitepaper
		`A3-ASWWYB-798JRYLJVD4-23DC2-86TVM-H43EB`,
		`A3-ASWWYB-798JRY-LJVD4-23DC2-86TVM-H43EB`,
	)
	fps := []string{
		// low entropy
		`A3-XXXXXX-XXXXXXXXXXX-XXXXX-XXXXX-XXXXX`,
		// lowercase
		`A3-xXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`,
	}
	return utils.Validate(r, tps, fps)
}
