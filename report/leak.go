package report

import (
	"strings"
	"time"
)

// Leak is a struct that contains information about some line of code that contains
// sensitive information as determined by the rules set in a gitleaks config
type Leak struct {
	Line       string    `json:"line"`
	LineNumber int       `json:"lineNumber"`
	Offender   string    `json:"offender"`
	Commit     string    `json:"commit"`
	Repo       string    `json:"repo"`
	RepoURL    string    `json:"repoURL"`
	LeakURL    string    `json:"leakURL"`
	Rule       string    `json:"rule"`
	Message    string    `json:"commitMessage"`
	Author     string    `json:"author"`
	Email      string    `json:"email"`
	File       string    `json:"file"`
	Date       time.Time `json:"date"`
	Tags       string    `json:"tags"`
}

// RedactLeak will replace the offending string with "REDACTED" in both
// the offender and line field of the leak which.
func RedactLeak(leak Leak) Leak {
	leak.Line = strings.Replace(leak.Line, leak.Offender, "REDACTED", -1)
	leak.Offender = "REDACTED"
	return leak
}
