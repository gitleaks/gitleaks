package detect

import (
	// "encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
)

// augmentGitFinding updates the start and end line numbers of a finding to include the
// delta from the git diff
func augmentGitFinding(finding report.Finding, textFragment *gitdiff.TextFragment, f *gitdiff.File) report.Finding {
	if !strings.HasPrefix(finding.Match, "file detected") {
		finding.StartLine += int(textFragment.NewPosition)
		finding.EndLine += int(textFragment.NewPosition)
	}

	if f.PatchHeader != nil {
		finding.Commit = f.PatchHeader.SHA
		finding.Message = f.PatchHeader.Message()
		if f.PatchHeader.Author != nil {
			finding.Author = f.PatchHeader.Author.Name
			finding.Email = f.PatchHeader.Author.Email
		}
		finding.Date = f.PatchHeader.AuthorDate.UTC().Format(time.RFC3339)
	}
	return finding
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// filter will dedupe and redact findings
func filter(findings []report.Finding, redact bool) []report.Finding {
	var retFindings []report.Finding
	for _, f := range findings {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.Replace(f.Match, f.Secret, "REDACTED", -1)
					betterMatch := strings.Replace(fPrime.Match, fPrime.Secret, "REDACTED", -1)
					log.Trace().Msgf("skipping %s finding (%s), %s rule takes precendence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact {
			f.Redact()
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func printFinding(f report.Finding) {
	// trim all whitespace and tabs from the line
	f.Line = strings.TrimSpace(f.Line)
	// trim all whitespace and tabs from the secret
	f.Secret = strings.TrimSpace(f.Secret)
	// trim all whitespace and tabs from the match
	f.Match = strings.TrimSpace(f.Match)

	matchInLineIDX := strings.Index(f.Line, f.Match)
	secretInMatchIdx := strings.Index(f.Match, f.Secret)

	start := f.Line[0:matchInLineIDX]
	startMatchIdx := 0
	if matchInLineIDX > 20 {
		startMatchIdx = matchInLineIDX - 20
		start = "..." + f.Line[startMatchIdx:matchInLineIDX]
	}

	matchBeginning := lipgloss.NewStyle().SetString(f.Match[0:secretInMatchIdx]).Foreground(lipgloss.Color("#f5d445"))
	secret := lipgloss.NewStyle().SetString(f.Secret).
		Bold(true).
		Italic(true).
		Foreground(lipgloss.Color("#f05c07"))
	matchEnd := lipgloss.NewStyle().SetString(f.Match[secretInMatchIdx+len(f.Secret):]).Foreground(lipgloss.Color("#f5d445"))
	lineEnd := f.Line[matchInLineIDX+len(f.Match):]
	if len(f.Secret) > 100 {
		secret = lipgloss.NewStyle().SetString(f.Secret[0:100] + "...").
			Bold(true).
			Italic(true).
			Foreground(lipgloss.Color("#f05c07"))
	}
	if len(lineEnd) > 20 {
		lineEnd = lineEnd[0:20] + "..."
	}

	finding := fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, secret, matchEnd, lineEnd)
	fmt.Printf("%-12s %s", "Finding:", finding)
	fmt.Printf("%-12s %s\n", "Secret:", secret)
	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)
	if f.File == "" {
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "File:", f.File)
	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	if f.Commit == "" {
		fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "Commit:", f.Commit)
	fmt.Printf("%-12s %s\n", "Author:", f.Author)
	fmt.Printf("%-12s %s\n", "Email:", f.Email)
	fmt.Printf("%-12s %s\n", "Date:", f.Date)
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
	fmt.Println("")
}

func containsDigit(s string) bool {
	for _, c := range s {
		switch c {
		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		}

	}
	return false
}
