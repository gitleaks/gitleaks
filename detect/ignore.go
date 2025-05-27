package detect

import "strconv"

type globIgnoreEntry struct {
	CommitIsGlob bool
	Commit       string

	FileIsGlob bool
	File       string

	RuleIsGlob bool
	Rule       string

	LineIsGlob bool
	Line       string
}

func (e globIgnoreEntry) Matches(commit string, file string, ruleId string, startLine int) bool {
	if !e.CommitIsGlob && commit != e.Commit {
		return false
	}
	if !e.FileIsGlob && file != e.File {
		return false
	}
	if !e.RuleIsGlob && ruleId != e.Rule {
		return false
	}
	line := strconv.Itoa(startLine)
	if !e.LineIsGlob && line != e.Line {
		return false
	}

	return true
}
