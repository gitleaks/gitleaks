package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGlobIgnoreMatches(t *testing.T) {
	tests := []struct {
		name        string
		commit      string
		file        string
		rule        string
		line        int
		ignoredGlob globIgnoreEntry
		wantMatch   bool
	}{
		// Exact match
		{
			name:   "Exact match",
			commit: "abc123",
			file:   "main.go",
			rule:   "RULE1",
			line:   100,
			ignoredGlob: globIgnoreEntry{
				Commit: "abc123",
				File:   "main.go",
				Rule:   "RULE1",
				Line:   "100",
			},
			wantMatch: true,
		},
		// Glob match on Commit
		{
			name:   "Commit is wildcard",
			commit: "anycommit",
			file:   "main.go",
			rule:   "RULE1",
			line:   100,
			ignoredGlob: globIgnoreEntry{
				Commit:       "*",
				CommitIsGlob: true,
				File:         "main.go",
				Rule:         "RULE1",
				Line:         "100",
			},
			wantMatch: true,
		},
		// Glob match on File
		{
			name:   "File is wildcard",
			commit: "abc123",
			file:   "whatever.go",
			rule:   "RULE1",
			line:   100,
			ignoredGlob: globIgnoreEntry{
				Commit:     "abc123",
				File:       "*",
				FileIsGlob: true,
				Rule:       "RULE1",
				Line:       "100",
			},
			wantMatch: true,
		},
		// Glob match on Rule
		{
			name:   "Rule is wildcard",
			commit: "abc123",
			file:   "main.go",
			rule:   "RULE2",
			line:   100,
			ignoredGlob: globIgnoreEntry{
				Commit:     "abc123",
				File:       "main.go",
				Rule:       "*",
				RuleIsGlob: true,
				Line:       "100",
			},
			wantMatch: true,
		},
		// Glob match on Line
		{
			name:   "Line is wildcard",
			commit: "abc123",
			file:   "main.go",
			rule:   "RULE1",
			line:   42,
			ignoredGlob: globIgnoreEntry{
				Commit:     "abc123",
				File:       "main.go",
				Rule:       "RULE1",
				Line:       "*",
				LineIsGlob: true,
			},
			wantMatch: true,
		},
		// All wildcards
		{
			name:   "Everything is wildcard",
			commit: "anycommit",
			file:   "anyfile.go",
			rule:   "anyrule",
			line:   1,
			ignoredGlob: globIgnoreEntry{
				Commit:       "*",
				CommitIsGlob: true,
				File:         "*",
				FileIsGlob:   true,
				Rule:         "*",
				RuleIsGlob:   true,
				Line:         "*",
				LineIsGlob:   true,
			},
			wantMatch: true,
		},
		// Mismatch in file
		{
			name:   "File mismatch",
			commit: "abc123",
			file:   "notmain.go",
			rule:   "RULE1",
			line:   100,
			ignoredGlob: globIgnoreEntry{
				Commit: "abc123",
				File:   "main.go",
				Rule:   "RULE1",
				Line:   "100",
			},
			wantMatch: false,
		},
		// Mismatch in line when not wildcard
		{
			name:   "Line mismatch with exact",
			commit: "abc123",
			file:   "main.go",
			rule:   "RULE1",
			line:   101,
			ignoredGlob: globIgnoreEntry{
				Commit: "abc123",
				File:   "main.go",
				Rule:   "RULE1",
				Line:   "100",
			},
			wantMatch: false,
		},
		// Wildcard line still matches any line number
		{
			name:   "Wildcard line matches different line",
			commit: "abc123",
			file:   "main.go",
			rule:   "RULE1",
			line:   999,
			ignoredGlob: globIgnoreEntry{
				Commit:     "abc123",
				File:       "main.go",
				Rule:       "RULE1",
				Line:       "*",
				LineIsGlob: true,
			},
			wantMatch: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.ignoredGlob.Matches(tc.commit, tc.file, tc.rule, tc.line)
			assert.Equal(t, tc.wantMatch, got)
		})
	}
}
