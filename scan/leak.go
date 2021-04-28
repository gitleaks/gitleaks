package scan

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/go-git/go-git/v5/plumbing/object"
)

// Leak is a struct that contains information about some line of code that contains
// sensitive information as determined by the rules set in a gitleaks config
type Leak struct {
	Line            string    `json:"line"`
	LineNumber      int       `json:"lineNumber"`
	Offender        string    `json:"offender"`
	OffenderEntropy float64   `json:"offenderEntropy"`
	Commit          string    `json:"commit"`
	Repo            string    `json:"repo"`
	RepoURL         string    `json:"repoURL"`
	LeakURL         string    `json:"leakURL"`
	Rule            string    `json:"rule"`
	Message         string    `json:"commitMessage"`
	Author          string    `json:"author"`
	Email           string    `json:"email"`
	File            string    `json:"file"`
	Date            time.Time `json:"date"`
	Tags            string    `json:"tags"`
}

// RedactLeak will replace the offending string with "REDACTED" in both
// the offender and line field of the leak which.
func RedactLeak(leak Leak) Leak {
	leak.Line = strings.Replace(leak.Line, leak.Offender, "REDACTED", -1)
	leak.Offender = "REDACTED"
	return leak
}

// NewLeak creates a new leak from common data all leaks must have, line, offender, linenumber
func NewLeak(line string, offender string, lineNumber int) Leak {
	return Leak{
		Line:            line,
		Offender:        offender,
		LineNumber:      lineNumber,
		OffenderEntropy: -1, // -1 means not checked
	}
}

// WithCommit adds commit data to the leak
func (leak Leak) WithCommit(commit *object.Commit) Leak {
	leak.Commit = commit.Hash.String()
	leak.Author = commit.Author.Name
	leak.Email = commit.Author.Email
	leak.Message = commit.Message
	leak.Date = commit.Author.When
	return leak
}

// WithEntropy adds OffenderEntropy data to the leak
func (leak Leak) WithEntropy(entropyLevel float64) Leak {
	leak.OffenderEntropy = math.Round(entropyLevel*1000) / 1000
	return leak
}

// Log logs a leak and redacts if necessary
func (leak Leak) Log(opts options.Options) {
	if !opts.Quiet && !opts.Verbose {
		return
	}
	if opts.Redact {
		leak = RedactLeak(leak)
	}
	if opts.Quiet {
		var b []byte
		b, _ = json.Marshal(leak)
		fmt.Println(string(b))
	} else {
		var b []byte
		b, _ = json.MarshalIndent(leak, "", "	")
		fmt.Println(string(b))
	}
}

// URL generates a url to the leak if leak.RepoURL is set
func (leak Leak) URL() string {
	if leak.RepoURL != "" {
		return fmt.Sprintf("%s/blob/%s/%s#L%d", leak.RepoURL, leak.Commit, leak.File, leak.LineNumber)
	}
	return ""
}
