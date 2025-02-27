package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Freemius() *config.Rule {
	// define rule
	r := config.Rule{
		RuleID:      "freemius-secret-key",
		Description: "Detected a Freemius secret key, potentially exposing sensitive information.",
		Regex:       regexp.MustCompile(`(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`),
		Keywords:    []string{"secret_key"},
		Path:        regexp.MustCompile(`(?i)\.php$`),
	}

	// validate
	tps := map[string]string{
		"file.php": `$config = array(
			"secret_key" => "sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE",
		);`,
	}
	// It's only used in PHP SDK snippet.
	// see https://freemius.com/help/documentation/wordpress-sdk/integrating-freemius-sdk/
	fps := map[string]string{
		// Invalid format: missing quotes around `secret_key`.
		"foo.php": `$config = array(
			secret_key => "sk_abcdefghijklmnopqrstuvwxyz123",
		);`,
		// Invalid format: missing quotes around the key value.
		"bar.php": `$config = array(
			"secret_key" => sk_abcdefghijklmnopqrstuvwxyz123,
		);`,
		// Invalid: different key name.
		"baz.php": `$config = array(
			"other_key" => "sk_abcdefghijklmnopqrstuvwxyz123",
		);`,
		// Invalid: file extension, should validate only .php files.
		"foo.html": `$config = array(
			"secret_key" => "sk_ubb4yN3mzqGR2x8#P7r5&@*xC$utE",
		);`,
	}

	return utils.ValidateWithPaths(r, tps, fps)
}
