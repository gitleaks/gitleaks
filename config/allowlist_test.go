package config

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
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
		assert.Equal(t, tt.commitAllowed, tt.allowlist.CommitAllowed(tt.commit))
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
