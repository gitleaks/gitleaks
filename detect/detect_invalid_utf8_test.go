//go:build gore2regex

package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// TestDetectRuleInvalidUTF8 guards against go-re2 stopping at the first
// invalid byte, which made rules silently miss secrets later in a fragment.
func TestDetectRuleInvalidUTF8(t *testing.T) {
	rule := config.Rule{
		RuleID:      "test-invalid-utf8",
		Description: "secret after invalid UTF-8",
		Regex:       regexp.MustCompile(`(?i)secret_key(?:.|\s){0,100}?\b[a-z0-9+/]{40}\b`),
	}
	d := NewDetector(config.Config{})
	raw := "secret_key\xd3\x00\x00\x00\x00\x00\x00\x00\x03\x93\x92\xcf\x00\x00\x00\x00\x00\x00\x00\x02\x92\xd9(z1Pdn06b3TnpG/9Gwj3ppPSOlAsu08Qw29PUW+eB\x92\xd3\x00\x00\x00\x00\x00\x00\x00\x01\xd9("
	f := Fragment{Raw: raw, FilePath: "secret.bin"}

	findings := d.detectRule(f, raw, rule, []*codec.EncodedSegment{})

	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Secret, "z1Pdn06b3TnpG/9Gwj3ppPSOlAsu08Qw29PUW+eB")
}
