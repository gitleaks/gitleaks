package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// Composio API keys: fixed prefix, then URL-safe nanoid characters.
// ak_ (project) and oak_ (org) carry 20 characters, uak_ (user) carries 43.
const composioKeyAlphabet = `[A-Za-z0-9_-]`

func ComposioProjectAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "composio-project-api-key",
		Description: "Found a Composio project API key, which grants access to a project's tools, connected accounts and triggers on the Composio platform.",
		Regex:       utils.GenerateUniqueTokenRegex(`ak_`+composioKeyAlphabet+`{20}`, false),
		Entropy:     3,
		Keywords:    []string{"ak_"},
	}

	tps := utils.GenerateSampleSecrets("composio", "ak_"+secrets.NewSecret(composioKeyAlphabet+`{20}`))
	tps = append(tps, `COMPOSIO_API_KEY="ak_Qbez9ytnft9XyXAGPL0-"`)
	fps := []string{
		// org and user keys contain "ak_" and must not match the project rule
		`COMPOSIO_API_KEY="oak_iuGvTZ4eiiy3umBWjwTt"`,
		`COMPOSIO_API_KEY="uak_TRFvy_o-mFznI3IyljByM5LL-SudKFv47vULpKuK2ai"`,
		`ak_test`,
		`ak_xxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}

func ComposioOrgAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "composio-org-api-key",
		Description: "Found a Composio organization API key, which grants administrative access across all projects in a Composio organization.",
		Regex:       utils.GenerateUniqueTokenRegex(`oak_`+composioKeyAlphabet+`{20}`, false),
		Entropy:     3,
		Keywords:    []string{"oak_"},
	}

	tps := utils.GenerateSampleSecrets("composio", "oak_"+secrets.NewSecret(composioKeyAlphabet+`{20}`))
	fps := []string{
		`COMPOSIO_API_KEY="ak_jI60uPF6adMkCuBFESjq"`,
		`oak_tree`,
	}
	return utils.Validate(r, tps, fps)
}

func ComposioUserAPIKey() *config.Rule {
	r := config.Rule{
		RuleID:      "composio-user-api-key",
		Description: "Found a Composio user API key, which acts as the user across every organization and project they can access on the Composio platform.",
		Regex:       utils.GenerateUniqueTokenRegex(`uak_`+composioKeyAlphabet+`{43}`, false),
		Entropy:     3,
		Keywords:    []string{"uak_"},
	}

	tps := utils.GenerateSampleSecrets("composio", "uak_"+secrets.NewSecret(composioKeyAlphabet+`{43}`))
	fps := []string{
		`COMPOSIO_API_KEY="ak_jI60uPF6adMkCuBFESjq"`,
		`uak_short`,
	}
	return utils.Validate(r, tps, fps)
}
