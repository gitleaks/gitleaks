package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func DjangoInsecureSecret() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "django-insecure-secret-key",
		Description: "Detected a Django insecure secret key, potentially compromising Django’s security protections against privilege escalation and remote code execution.",
		Regex:       regexp.MustCompile(`["'](django-insecure-[^"']{1,250})["']`),
		Path:        regexp.MustCompile(`(?i)\.py$`),
		SecretGroup: 1,
		Keywords:    []string{"django-insecure-"},
	}

	// validate
	tps := map[string]string{
		"setting.py": `SECRET_KEY = "django-insecure-123456789!%_&*^)abcdef"`,
	}

	return utils.ValidateWithPaths(r, tps, nil)
}
