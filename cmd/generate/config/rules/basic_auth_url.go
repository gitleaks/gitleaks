package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func BasicAuthURL() *config.Rule {
	r := config.Rule{
		RuleID:      "basic-auth-url",
		Description: "Discovered credentials embedded in a URL, which may compromise the URL-accessed resource.",
		Regex:       regexp.MustCompile(`(?i)\bhttps?://([^:/@\s]{3,}:(?:%[0-9a-f]{2}|[\w=~.+!$&'()*+,;\-]){8,})@`),
		Keywords:    []string{"http://", "https://"},
		Entropy:     2,
		Allowlists: []*config.Allowlist{
			{
				Regexes: []*regexp.Regexp{
					regexp.MustCompile(`(?i)[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\*+|x+)`),
					regexp.MustCompile(`[^:]+:\[[^]]+]`),
					regexp.MustCompile(`<[^:>]+:[^>]+>`),
					regexp.MustCompile(`[^:]+:\$\{?\w+}?`),
					regexp.MustCompile(`\$\{?\w+}?:\$\{?\w+}?`),
				},
			},
		},
	}

	tps := []string{
		`baseurl = https://PSVC-ART-RO:abc123SECRET456D@repo.example.invalid/artifactory/unit-agent-prod-rpm/shared/`,
		`baseurl = https://PSVC-ART-RO:abc123%2BSECRET456D@repo.example.invalid/artifactory/unit-agent-prod-rpm/shared/`,
		`proxy = "http://deploy-user:pQ9wTxu4Fg@proxy.example.invalid:8080"`,
	}
	fps := []string{
		`baseurl = https://username:password@repo.example.invalid/artifactory/unit-agent-prod-rpm/shared/`,
		`baseurl = https://<user:password>@repo.example.invalid/artifactory/unit-agent-prod-rpm/shared/`,
		`proxy = "http://${PROXY_USER}:${PROXY_PASSWORD}@proxy.example.invalid:8080"`,
		`proxy = "http://user:[PASSWORD]@proxy.example.invalid:8080"`,
		`https://example.com/path?not=basic-auth`,
	}
	return utils.Validate(r, tps, fps)
}
