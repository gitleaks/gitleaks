package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CohereAPIToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "cohere-api-token",
		Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`, false),
		Entropy:     4,
		Keywords: []string{
			"cohere",
			"CO_API_KEY",
		},
	}

	// validate
	tps := []string{
		utils.GenerateSampleSecret("cohere", secrets.NewSecret(`[a-zA-Z0-9]{40}`)),
		// https://github.com/cohere-ai/cohere-go/blob/abe8044073ed498ffbb206a602d03c2414b64512/client/client.go#L38C30-L38C40
		`export CO_API_KEY=` + secrets.NewSecret(`[a-zA-Z0-9]{40}`),
	}
	fps := []string{
		`CO_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
	}
	return utils.Validate(r, tps, fps)
}
