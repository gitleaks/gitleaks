package detect

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestGitleaksAllowLine(t *testing.T) {
	tests := map[string]struct {
		raw                 string
		ignoreGitleaksAllow bool
		expectedFindings    int
	}{
		"existing same-line directive": {
			raw:              "api_key = SECRET_ALPHA # gitleaks:allow",
			expectedFindings: 0,
		},
		"directive before finding": {
			raw: `# gitleaks:allow_line:+1
api_key = SECRET_ALPHA`,
			expectedFindings: 0,
		},
		"directive after finding": {
			raw: `api_key = SECRET_ALPHA
# gitleaks:allow_line:-1`,
			expectedFindings: 0,
		},
		"directive with a multi-line offset": {
			raw: `# gitleaks:allow_line:+3
first
second
api_key = SECRET_ALPHA`,
			expectedFindings: 0,
		},
		"directive targeting another line": {
			raw: `# gitleaks:allow_line:+1
not a secret
api_key = SECRET_ALPHA`,
			expectedFindings: 1,
		},
		"directive without a signed offset": {
			raw:              "api_key = SECRET_ALPHA # gitleaks:allow_line:1",
			expectedFindings: 1,
		},
		"directive targeting the next line does not allow the current line": {
			raw:              "api_key = SECRET_ALPHA # gitleaks:allow_line:+1",
			expectedFindings: 1,
		},
		"directive with an invalid suffix": {
			raw:              "api_key = SECRET_ALPHA # gitleaks:allow_line:+1extra",
			expectedFindings: 1,
		},
		"directive with a zero offset": {
			raw:              "api_key = SECRET_ALPHA # gitleaks:allow_line:+0",
			expectedFindings: 0,
		},
		"ignore allow directives": {
			raw: `# gitleaks:allow_line:+1
api_key = SECRET_ALPHA`,
			ignoreGitleaksAllow: true,
			expectedFindings:    1,
		},
	}

	rule := config.Rule{
		RuleID: "test-rule",
		Regex:  regexp.MustCompile(`SECRET_[A-Z]+`),
	}
	cfg := config.Config{
		Rules: map[string]config.Rule{
			rule.RuleID: rule,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			detector := NewDetector(cfg)
			detector.IgnoreGitleaksAllow = test.ignoreGitleaksAllow
			fragment := Fragment{
				Raw:       test.raw,
				FilePath:  "test.txt",
				StartLine: 42,
			}

			findings := detector.Detect(fragment)

			require.Len(t, findings, test.expectedFindings)
		})
	}
}
