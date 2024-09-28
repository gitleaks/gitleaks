package config

import (
	"testing"
)

func Test_IsBoundaryBesideNonWord(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		patterns []string
		expected bool
	}{
		// Valid
		{
			name: "word-boundary before word character",
			patterns: []string{
				`\b\w`,
				`\b\w*`,
				`\b\w+`,
				`\b\w?`,
				`\b\w{10}`,
				`\b\w{0,10}`,
				`\b[A-Za-z0-9_]`,
				`\b[A-Za-z0-9_]*`,
				`\b[A-Za-z0-9_]+`,
				`\b[A-Za-z0-9_]?`,
				`\b[A-Za-z0-9_]{10}`,
				`\b[A-Za-z0-9_]{0,10}`,
				`\bvalid`,
				`\b(foo1|bar2)`,
				`\b(?:foo1|bar2)`,
				`\b(?:foo1|(?:bar2)(?:baz3|-qux4))`,
				`\bglpat-[\w-]{20}`,
			},
			expected: false,
		},
		{
			name: "word-boundary after word character",
			patterns: []string{
				`\w\b`,
				`\w*\b`,
				`\w+\b`,
				`\w?\b`,
				`\w{10}\b`,
				`\w{0,10}\b`,
				`[A-Za-z0-9_]\b`,
				`[A-Za-z0-9_]*\b`,
				`[A-Za-z0-9_]+\b`,
				`[A-Za-z0-9_]?\b`,
				`[A-Za-z0-9_]{10}\b`,
				`[A-Za-z0-9_]{0,10}\b`,
				`valid\b`,
				`(foo1|bar2)\b`,
				`(?:foo1|bar2)\b`,
			},
			expected: false,
		},
		// Invalid
		{
			name: "word-boundary before non-word character",
			patterns: []string{
				`\b.`,
				`\b-`,
				`\b-*`,
				`\b-+`,
				`\b-?`,
				`\b-{10}`,
				`\b-{0,10}`,
				`\b[A-Za-z0-9_*-]`,
				`\b[A-Za-z0-9_*-]*`,
				`\b[A-Za-z0-9_*-]+`,
				`\b[A-Za-z0-9_*-]?`,
				`\b[A-Za-z0-9_*-]{10}`,
				`\b[A-Za-z0-9_*-]{0,10}`,
				`\b-invalid`,
				`\b(-foo1|bar2)`,
				`\b(?:-foo1|bar2)`,
				`\b(?:foo1|(?:bar2)?(?:baz3|-qux4))`,
				`\b(?:foo1|(?:bar2)?(?:baz3|(quux5|(?:-corge6|grault7)qux4)))`,
			},
			expected: true,
		},
		{
			name: "word-boundary after non-word character",
			patterns: []string{
				`.\b`,
				`-\b`,
				`-*\b`,
				`-+\b`,
				`-?\b`,
				`-{10}\b`,
				`-{0,10}\b`,
				`[A-Za-z0-9_*-]\b`,
				`[A-Za-z0-9_*-]*\b`,
				`[A-Za-z0-9_*-]+\b`,
				`[A-Za-z0-9_*-]?\b`,
				`[A-Za-z0-9_*-]{10}\b`,
				`[A-Za-z0-9_*-]{0,10}\b`,
				`invalid-\b`,
				`(foo1|bar2-)\b`,
				`(?:foo1|bar2-)\b`,
				`(?:foo1|(?:baz3|qux4-)(?:bar2)?)\b`,
				`(?:foo1|(?:baz3|qux4(quux5|(?:corge6-|grault7)))(?:bar2)?)\b`,
				`glpat-[\w-]{20}\b`,
			},
			expected: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, pattern := range c.patterns {
				actual, err := IsBoundaryBesideNonWord(pattern)
				if err != nil {
					t.Fatalf("Failed to check word boundary: %v", err)
				}

				if actual != c.expected {
					t.Errorf("Expected %v, got %v: %s", c.expected, actual, pattern)
				}
			}
		})
	}
}
