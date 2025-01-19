package detect

import (
	// "encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/charmbracelet/lipgloss"
	"github.com/gitleaks/go-gitdiff/gitdiff"
)

// augmentGitFinding updates the start and end line numbers of a finding to include the
// delta from the git diff
func augmentGitFinding(scmPlatform scm.Platform, remoteUrl string, finding report.Finding, textFragment *gitdiff.TextFragment, f *gitdiff.File) report.Finding {
	if !strings.HasPrefix(finding.Match, "file detected") {
		finding.StartLine += int(textFragment.NewPosition)
		finding.EndLine += int(textFragment.NewPosition)
	}

	if f.PatchHeader != nil {
		finding.Commit = f.PatchHeader.SHA
		if f.PatchHeader.Author != nil {
			finding.Author = f.PatchHeader.Author.Name
			finding.Email = f.PatchHeader.Author.Email
		}
		finding.Date = f.PatchHeader.AuthorDate.UTC().Format(time.RFC3339)
		finding.Message = f.PatchHeader.Message()
		// Results from `git diff` shouldn't have a link.
		if finding.Commit != "" {
			finding.Link = createScmLink(scmPlatform, remoteUrl, finding)
		}
	}
	return finding
}

var linkCleaner = strings.NewReplacer(
	" ", "%20",
	"%", "%25",
)

func createScmLink(scmPlatform scm.Platform, remoteUrl string, finding report.Finding) string {
	if scmPlatform == scm.NoPlatform {
		return ""
	}

	// Clean the path.
	var (
		filePath = linkCleaner.Replace(finding.File)
		ext      = strings.ToLower(filepath.Ext(filePath))
	)

	switch scmPlatform {
	case scm.GitHubPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteUrl, finding.Commit, filePath)
		if ext == ".ipynb" || ext == ".md" {
			link += "?plain=1"
		}
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-L%d", finding.EndLine)
		}
		return link
	case scm.GitLabPlatform:
		link := fmt.Sprintf("%s/blob/%s/%s", remoteUrl, finding.Commit, filePath)
		if finding.StartLine != 0 {
			link += fmt.Sprintf("#L%d", finding.StartLine)
		}
		if finding.EndLine != finding.StartLine {
			link += fmt.Sprintf("-%d", finding.EndLine)
		}
		return link
	default:
		// This should never happen.
		return ""
	}
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
func filter(findings []report.Finding, redact uint) []report.Finding {
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
					logging.Trace().Msgf("skipping %s finding (%s), %s rule takes precedence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact > 0 {
			f.Redact(redact)
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func printFinding(f report.Finding, noColor bool) {
	// trim all whitespace and tabs
	f.Line = strings.TrimSpace(f.Line)
	f.Secret = strings.TrimSpace(f.Secret)
	f.Match = strings.TrimSpace(f.Match)

	isFileMatch := strings.HasPrefix(f.Match, "file detected:")
	skipColor := noColor
	finding := ""
	var secret lipgloss.Style

	// Matches from filenames do not have a |line| or |secret|
	if !isFileMatch {
		matchInLineIDX := strings.Index(f.Line, f.Match)
		secretInMatchIdx := strings.Index(f.Match, f.Secret)

		skipColor = false

		if matchInLineIDX == -1 || noColor {
			skipColor = true
			matchInLineIDX = 0
		}

		start := f.Line[0:matchInLineIDX]
		startMatchIdx := 0
		if matchInLineIDX > 20 {
			startMatchIdx = matchInLineIDX - 20
			start = "..." + f.Line[startMatchIdx:matchInLineIDX]
		}

		matchBeginning := lipgloss.NewStyle().SetString(f.Match[0:secretInMatchIdx]).Foreground(lipgloss.Color("#f5d445"))
		secret = lipgloss.NewStyle().SetString(f.Secret).
			Bold(true).
			Italic(true).
			Foreground(lipgloss.Color("#f05c07"))
		matchEnd := lipgloss.NewStyle().SetString(f.Match[secretInMatchIdx+len(f.Secret):]).Foreground(lipgloss.Color("#f5d445"))

		lineEndIdx := matchInLineIDX + len(f.Match)
		if len(f.Line)-1 <= lineEndIdx {
			lineEndIdx = len(f.Line)
		}

		lineEnd := f.Line[lineEndIdx:]

		if len(f.Secret) > 100 {
			secret = lipgloss.NewStyle().SetString(f.Secret[0:100] + "...").
				Bold(true).
				Italic(true).
				Foreground(lipgloss.Color("#f05c07"))
		}
		if len(lineEnd) > 20 {
			lineEnd = lineEnd[0:20] + "..."
		}

		finding = fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, secret, matchEnd, lineEnd)
	}

	if skipColor || isFileMatch {
		fmt.Printf("%-12s %s\n", "Finding:", f.Match)
		fmt.Printf("%-12s %s\n", "Secret:", f.Secret)
	} else {
		fmt.Printf("%-12s %s", "Finding:", finding)
		fmt.Printf("%-12s %s\n", "Secret:", secret)
	}

	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)
	if f.File == "" {
		fmt.Println("")
		return
	}
	if len(f.Tags) > 0 {
		fmt.Printf("%-12s %s\n", "Tags:", f.Tags)
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
	if f.Link != "" {
		fmt.Printf("%-12s %s\n", "Link:", f.Link)
	}
	fmt.Println("")
}

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}
