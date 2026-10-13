package sources

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Test_readUntilSafeBoundary(t *testing.T) {
	// Arrange
	cases := []struct {
		name     string
		r        io.Reader
		expected string
	}{
		// Current split is fine, exit early.
		{
			name:     "safe original split - LF",
			r:        strings.NewReader("abc\n\ndefghijklmnop\n\nqrstuvwxyz"),
			expected: "abc\n\n",
		},
		{
			name:     "safe original split - CRLF",
			r:        strings.NewReader("a\r\n\r\nbcdefghijklmnop\n"),
			expected: "a\r\n\r\n",
		},
		// Current split is bad, look for a better one.
		{
			name:     "safe split - LF",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\n",
		},
		{
			name:     "safe split - CRLF",
			r:        strings.NewReader("abcdefg\r\nhijklmnop\r\n\r\nqrstuvwxyz"),
			expected: "abcdefg\r\nhijklmnop\r\n\r\n",
		},
		{
			name:     "safe split - blank line",
			r:        strings.NewReader("abcdefg\nhijklmnop\n\t  \t\nqrstuvwxyz"),
			expected: "abcdefg\nhijklmnop\n\t  \t\n",
		},
		// Current split is bad, exhaust options.
		{
			name:     "no safe split",
			r:        strings.NewReader("abcdefg\nhijklmnopqrstuvwxyz"),
			expected: "abcdefg\nhijklmnopqrstuvwx",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := make([]byte, 5)
			n, err := c.r.Read(buf)
			require.NoError(t, err)

			// Act
			reader := bufio.NewReader(c.r)
			peekBuf := bytes.NewBuffer(buf[:n])
			err = readUntilSafeBoundary(reader, n, 20, peekBuf)
			require.NoError(t, err)

			// Assert
			t.Log(peekBuf.String())
			require.Equal(t, c.expected, peekBuf.String())
		})
	}
}

func TestShouldSkipPath(t *testing.T) {
	mustCompile := func(pat string) []*regexp.Regexp {
		return []*regexp.Regexp{regexp.MustCompile(pat)}
	}

	tests := map[string]struct {
		allowlist *config.Allowlist
		path      string
		want      bool
	}{
		"or condition, path matches": {
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Paths:          mustCompile(`\.md$`),
			},
			path: "docs/README.md",
			want: true,
		},
		"or condition, path does not match": {
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Paths:          mustCompile(`\.md$`),
			},
			path: "main.go",
			want: false,
		},
		"or condition with regexes, path alone still allowlists": {
			// Under OR any single criterion is sufficient, so skipping on the
			// path without reading the file is correct.
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchOr,
				Paths:          mustCompile(`\.md$`),
				Regexes:        mustCompile(`PLACEHOLDER`),
			},
			path: "docs/README.md",
			want: true,
		},
		"and condition with regexes, must not skip on path alone": {
			// The regression this guards: the regex can only be evaluated
			// against file content, so skipping here would hide real secrets in
			// every .md file rather than allowlisting one pattern within them.
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Paths:          mustCompile(`\.md$`),
				Regexes:        mustCompile(`PLACEHOLDER`),
			},
			path: "docs/README.md",
			want: false,
		},
		"and condition with stopwords, must not skip on path alone": {
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Paths:          mustCompile(`\.md$`),
				StopWords:      []string{"example"},
			},
			path: "docs/README.md",
			want: false,
		},
		"and condition with commits, must not skip on path alone": {
			// Commits cannot be evaluated during enumeration, and a non-git
			// source has no commit at all, so this allowlist can never match
			// there. Skipping on the path would drop the file for an allowlist
			// that will never apply.
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Paths:          mustCompile(`\.md$`),
				Commits:        []string{"0000000000000000000000000000000000000000"},
			},
			path: "docs/README.md",
			want: false,
		},
		"nil allowlist entry is skipped rather than panicking": {
			allowlist: nil,
			path:      "docs/README.md",
			want:      false,
		},
		"and condition, paths are the only criterion": {
			// Nothing else has to be checked, so the path is sufficient.
			allowlist: &config.Allowlist{
				MatchCondition: config.AllowlistMatchAnd,
				Paths:          mustCompile(`\.md$`),
			},
			path: "docs/README.md",
			want: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Validate is not nil-safe upstream, and a nil entry never arrives
			// from a validated config -- it arrives from one built in code.
			// shouldSkipPath still has to survive it.
			if tt.allowlist != nil {
				require.NoError(t, tt.allowlist.Validate())
			}
			cfg := &config.Config{Allowlists: []*config.Allowlist{tt.allowlist}}
			assert.Equal(t, tt.want, shouldSkipPath(cfg, tt.path))
		})
	}
}

func TestShouldSkipPathNilConfig(t *testing.T) {
	assert.False(t, shouldSkipPath(nil, "any/path.md"))
}
