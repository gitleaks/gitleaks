package config

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestCommitAllowed(t *testing.T) {
	tests := []struct {
		allowlist     Allowlist
		commit        string
		commitAllowed bool
	}{
		{
			allowlist: Allowlist{
				Commits: []string{"commitA"},
			},
			commit:        "commitA",
			commitAllowed: true,
		},
		{
			allowlist: Allowlist{
				Commits: []string{"commitB"},
			},
			commit:        "commitA",
			commitAllowed: false,
		},
		{
			allowlist: Allowlist{
				Commits: []string{"commitB"},
			},
			commit:        "",
			commitAllowed: false,
		},
	}
	for _, tt := range tests {
		isAllowed, _ := tt.allowlist.CommitAllowed(tt.commit)
		assert.Equal(t, tt.commitAllowed, isAllowed)
	}
}

func TestRegexAllowed(t *testing.T) {
	tests := []struct {
		allowlist    Allowlist
		secret       string
		regexAllowed bool
	}{
		{
			allowlist: Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile("matchthis")},
			},
			secret:       "a secret: matchthis, done",
			regexAllowed: true,
		},
		{
			allowlist: Allowlist{
				Regexes: []*regexp.Regexp{regexp.MustCompile("matchthis")},
			},
			secret:       "a secret",
			regexAllowed: false,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.regexAllowed, tt.allowlist.RegexAllowed(tt.secret))
	}
}

func TestPathAllowed(t *testing.T) {
	tests := []struct {
		allowlist   Allowlist
		path        string
		pathAllowed bool
	}{
		{
			allowlist: Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile("path")},
			},
			path:        "a path",
			pathAllowed: true,
		},
		{
			allowlist: Allowlist{
				Paths: []*regexp.Regexp{regexp.MustCompile("path")},
			},
			path:        "a ???",
			pathAllowed: false,
		},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.pathAllowed, tt.allowlist.PathAllowed(tt.path))
	}
}

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		input    Allowlist
		expected Allowlist
		wantErr  error
	}{
		"empty conditions": {
			input:   Allowlist{},
			wantErr: errors.New("[[rules.allowlists]] must contain at least one check for: commits, paths, regexes, or stopwords"),
		},
		"deduplicated commits and stopwords": {
			input: Allowlist{
				Commits:   []string{"commitA", "commitB", "commitA"},
				StopWords: []string{"stopwordA", "stopwordB", "stopwordA"},
			},
			expected: Allowlist{
				Commits:   []string{"commitA", "commitB"},
				StopWords: []string{"stopwordA", "stopwordB"},
			},
		},
	}

	for _, tt := range tests {
		// Expected an error.
		err := tt.input.Validate()
		if err != nil {
			if tt.wantErr == nil {
				t.Fatalf("Received unexpected error: %v", err)
			} else if !assert.EqualError(t, err, tt.wantErr.Error()) {
				t.Fatalf("Received unexpected error, expected '%v', got '%v'", tt.wantErr, err)
			}
		} else {
			if tt.wantErr != nil {
				t.Fatalf("Did not receive expected error: %v", tt.wantErr)
			}
		}

		var (
			regexComparer = func(x, y *regexp.Regexp) bool {
				// Compare the string representation of the regex patterns.
				if x == nil || y == nil {
					return x == y
				}
				return x.String() == y.String()
			}
			arrayComparer = func(a, b string) bool {
				return a < b
			}
			opts = cmp.Options{
				cmp.Comparer(regexComparer),
				cmpopts.SortSlices(arrayComparer),
			}
		)
		if diff := cmp.Diff(tt.input, tt.expected, opts); diff != "" {
			t.Errorf("diff: (-want +got)\n%s", diff)
		}
	}
}
