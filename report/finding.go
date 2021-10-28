package report

import "strings"

// Finding contains information about strings that
// have been captured by a tree-sitter query.
type Finding struct {
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string

	// Content contains the full content of what is matched in
	// the tree-sitter query.
	Content string

	// File is the name of the file containing the finding
	File string

	Commit string

	// Entropy is the shannon entropy of Value
	Entropy float64

	Author  string
	Email   string
	Date    string
	Message string
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact() {
	f.Line = strings.Replace(f.Line, f.Content, "REDACTED", -1)
	f.Content = "REDACT"
}
