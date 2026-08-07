package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// SpringPlaceholderSecret detects Spring Boot property placeholders with hardcoded default secrets in YAML files.
func SpringPlaceholderSecret() *config.Rule {
	r := config.Rule{
		RuleID:      "spring-placeholder-with-secret",
		Description: "Secret embedded as default value in Spring Boot property placeholders, such as `${VAR:secret}` in YAML files.",
		Regex:       regexp.MustCompile(`(?i)\$\{[A-Z0-9_]+:([A-Za-z0-9+/=_-]{20,})\}`),
		SecretGroup: 1,
		Path:        regexp.MustCompile(`(?i)\.ya?ml$`),
		Tags:        []string{"secret", "spring", "placeholder", "default-value"},
	}

	tps := map[string]string{
		"application.yaml": `openai:
  api-key: ${OPENAI_API_KEY:gsk_wewew222dfrffdsASRerTwr}`,
		"application.yml": `openai:
  api-key: ${OPENAI_API_KEY:gsk_wewew222dfrffdsASRerTwr}`,
	}
	fps := map[string]string{
		"application.yaml": `openai:
  api-key: ${OPENAI_API_KEY:default}`,
		"application.yml": `openai:
  api-key: ${OPENAI_API_KEY}`,
	}

	return utils.ValidateWithPaths(r, tps, fps)
}
