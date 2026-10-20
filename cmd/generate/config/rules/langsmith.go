package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LangSmithPersonalAccessToken() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langsmith-personal-access-token",
		Description: "Detected a LangSmith Personal Access Token.",
		Regex:       utils.GenerateUniqueTokenRegex(`lsv2_pt_`+utils.Hex("32")+`_`+utils.Hex("10"), false),
		Entropy:     3,
		Keywords:    []string{"lsv2_pt_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("langsmith", newLangSmithKey("lsv2_pt_"))
	tps = append(tps, `LANGSMITH_API_KEY="`+newLangSmithKey("lsv2_pt_")+`"`)
	fps := []string{
		// Too short
		"lsv2_pt_0f1e2d3c4b5a69788796a5b4c3d2e1_a1b2c3d4e5",
		// Non-hex characters
		"lsv2_pt_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_a1b2c3d4e5",
		// Wrong suffix length
		"lsv2_pt_0f1e2d3c4b5a69788796a5b4c3d2e1f0_a1b2c3",
		// Service key, not personal access token
		newLangSmithKey("lsv2_sk_"),
	}
	return utils.Validate(r, tps, fps)
}

func LangSmithServiceKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langsmith-service-key",
		Description: "Detected a LangSmith Service Key.",
		Regex:       utils.GenerateUniqueTokenRegex(`lsv2_sk_`+utils.Hex("32")+`_`+utils.Hex("10"), false),
		Entropy:     3,
		Keywords:    []string{"lsv2_sk_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("langsmith", newLangSmithKey("lsv2_sk_"))
	tps = append(tps, `LANGSMITH_API_KEY=`+newLangSmithKey("lsv2_sk_"))
	fps := []string{
		// Too short
		"lsv2_sk_9a8b7c6d5e4f30211203f4e5d6c7b8_5e4d3c2b1a",
		// Non-hex characters
		"lsv2_sk_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_5e4d3c2b1a",
		// Personal access token, not service key
		newLangSmithKey("lsv2_pt_"),
	}
	return utils.Validate(r, tps, fps)
}

func LangSmithTracingKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "langsmith-tracing-key",
		Description: "Detected a LangSmith Tracing Key.",
		Regex:       utils.GenerateUniqueTokenRegex(`lsv2_tr_`+utils.Hex("32")+`_`+utils.Hex("10"), false),
		Entropy:     3,
		Keywords:    []string{"lsv2_tr_"},
	}

	// validate
	tps := utils.GenerateSampleSecrets("langsmith", newLangSmithKey("lsv2_tr_"))
	tps = append(tps, `LANGSMITH_API_KEY=`+newLangSmithKey("lsv2_tr_"))
	fps := []string{
		// Too short
		"lsv2_tr_4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a_9f8e7d6c5b",
		// Non-hex characters
		"lsv2_tr_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_9f8e7d6c5b",
		// Personal access token, not tracing key
		newLangSmithKey("lsv2_pt_"),
	}
	return utils.Validate(r, tps, fps)
}

func newLangSmithKey(prefix string) string {
	return prefix + secrets.NewSecret(utils.Hex("32")) + "_" + secrets.NewSecret(utils.Hex("10"))
}
