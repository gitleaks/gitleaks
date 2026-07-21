package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PineconeApiKey() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "pinecone-api-key",
		Description: "Identified a Pinecone API Key, which may grant access to vector database indexes backing RAG and AI applications, risking exfiltration of embedded data.",
		Regex:       utils.GenerateUniqueTokenRegex(`pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}`, false),
		Entropy:     3,
		Keywords: []string{
			"pcsk_",
		},
	}

	// validate
	tps := utils.GenerateSampleSecrets("pinecone",
		"pcsk_"+secrets.NewSecret(`[A-Za-z0-9]{5}`)+"_"+secrets.NewSecret(utils.AlphaNumeric("63")))
	fps := []string{
		// Too short body.
		`pinecone_api_key = "pcsk_abcde_tooShort"`,
		// Wrong prefix.
		`pccm_abcde_0123456789012345678901234567890123456789012345678901234567890123`,
	}
	return utils.Validate(r, tps, fps)
}
