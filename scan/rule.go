package scan

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v6/config"
	"github.com/zricethezav/gitleaks/v6/manager"

	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
)

const (
	diffAddPrefix           = "+"
	diffAddFilePrefix       = "+++ b"
	diffAddFilePrefixSlash  = "+++ b/"
	diffLineSignature       = " @@"
	diffLineSignaturePrefix = "@@ "
	defaultLineNumber       = -1
)

// CheckRules accepts bundle and checks each rule defined in the config against the bundle's content.
func (repo *Repo) CheckRules(bundle *Bundle) {
	filename := filepath.Base(bundle.FilePath)
	path := filepath.Dir(bundle.FilePath)

	bundle.lineLookup = make(map[string]bool)

	// We want to check if there is a allowlist for this file
	if len(repo.config.Allowlist.Files) != 0 {
		for _, reFileName := range repo.config.Allowlist.Files {
			if RegexMatched(filename, reFileName) {
				log.Debugf("allowlisted file found, skipping scan of file: %s", filename)
				return
			}
		}
	}

	// We want to check if there is a allowlist for this path
	if len(repo.config.Allowlist.Paths) != 0 {
		for _, reFilePath := range repo.config.Allowlist.Paths {
			if RegexMatched(path, reFilePath) {
				log.Debugf("file in allowlisted path found, skipping scan of file: %s", filename)
				return
			}
		}
	}

	for _, rule := range repo.config.Rules {
		start := time.Now()

		// For each rule we want to check filename allowlists
		if isAllowListed(filename, rule.AllowList.Files) || isAllowListed(path, rule.AllowList.Paths) {
			continue
		}

		// If it has fileNameRegex and it doesnt match we continue to next rule
		if ruleContainFileRegex(rule) && !RegexMatched(filename, rule.File) {
			continue
		}

		// If it has filePathRegex and it doesnt match we continue to next rule
		if ruleContainPathRegex(rule) && !RegexMatched(path, rule.Path) {
			continue
		}

		// If it doesnt contain a Content regex then it is a filename regex match
		if !ruleContainRegex(rule) {
			repo.Manager.SendLeaks(manager.Leak{
				LineNumber: defaultLineNumber,
				Line:       "N/A",
				Offender:   "Filename/path offender: " + filename,
				Commit:     bundle.Commit.Hash.String(),
				Repo:       repo.Name,
				Message:    bundle.Commit.Message,
				Rule:       rule.Description,
				Author:     bundle.Commit.Author.Name,
				Email:      bundle.Commit.Author.Email,
				Date:       bundle.Commit.Author.When,
				Tags:       strings.Join(rule.Tags, ", "),
				File:       filename,
				Operation:  diffOpToString(bundle.Operation),
			})
		} else {
			//otherwise we check if it matches Content regex
			locs := rule.Regex.FindAllIndex([]byte(bundle.Content), -1)
			if len(locs) != 0 {
				for _, loc := range locs {
					start := loc[0]
					end := loc[1]
					for start != 0 && bundle.Content[start] != '\n' {
						start--
					}

					if bundle.Content[start] == '\n' {
						start++
					}

					for end < len(bundle.Content)-1 && bundle.Content[end] != '\n' {
						end++
					}

					line := bundle.Content[start:end]
					offender := bundle.Content[loc[0]:loc[1]]
					groups := rule.Regex.FindStringSubmatch(offender)

					if isAllowListed(line, append(rule.AllowList.Regexes, repo.config.Allowlist.Regexes...)) {
						continue
					}

					if len(rule.Entropies) != 0 && !trippedEntropy(groups, rule) {
						continue
					}

					// 0 is a match for the full regex pattern
					if 0 < rule.ReportGroup && rule.ReportGroup < len(groups) {
						offender = groups[rule.ReportGroup]
					}

					leak := manager.Leak{
						LineNumber: defaultLineNumber,
						Line:       line,
						Offender:   offender,
						Commit:     bundle.Commit.Hash.String(),
						Repo:       repo.Name,
						Message:    bundle.Commit.Message,
						Rule:       rule.Description,
						Author:     bundle.Commit.Author.Name,
						Email:      bundle.Commit.Author.Email,
						Date:       bundle.Commit.Author.When,
						Tags:       strings.Join(rule.Tags, ", "),
						File:       bundle.FilePath,
						Operation:  diffOpToString(bundle.Operation),
					}

					// only search for line numbers on non-deletions
					if bundle.Operation != fdiff.Delete {
						extractAndInjectLineNumber(&leak, bundle, repo)
					}

					repo.Manager.SendLeaks(leak)
				}
			}
		}

		repo.Manager.RecordTime(manager.RegexTime{
			Time:  howLong(start),
			Regex: rule.Regex.String(),
		})
	}
}

// RegexMatched matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func RegexMatched(f interface{}, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	switch f.(type) {
	case nil:
		return false
	case string:
		if re.FindString(f.(string)) != "" {
			return true
		}
		return false
	case *object.File:
		if re.FindString(f.(*object.File).Name) != "" {
			return true
		}
		return false
	}
	return false
}

// diffOpToString converts a fdiff.Operation to a string
func diffOpToString(operation fdiff.Operation) string {
	switch operation {
	case fdiff.Add:
		return "addition"
	case fdiff.Equal:
		return "equal"
	default:
		return "deletion"
	}
}

// extractAndInjectLine accepts a leak, bundle, and repo which it uses to do a reverse search in order to extract
// the line number of a historic or present leak. The function is only called when the git operation is an addition
// or none, it does not get called when the git operation is deletion.
func extractAndInjectLineNumber(leak *manager.Leak, bundle *Bundle, repo *Repo) {
	var err error

	switch bundle.scanType {
	case patchScan:
		if bundle.Patch == "" {
			return
		}

		// This is needed as some patches generate strings that are larger than
		// scanners max size (MaxScanTokenSize = 64 * 1024)
		// https://github.com/zricethezav/gitleaks/issues/413
		buf := make([]byte, len(bundle.Patch))
		scanner := bufio.NewScanner(strings.NewReader(bundle.Patch))
		scanner.Buffer(buf, len(bundle.Patch))
		scanner.Split(bufio.ScanLines)

		currFile := ""
		currLine := 0
		currStartDiffLine := 0

		for scanner.Scan() {
			txt := scanner.Text()
			if strings.HasPrefix(txt, diffAddFilePrefix) {
				currStartDiffLine = 1
				currLine = 0
				currFile = strings.Split(txt, diffAddFilePrefixSlash)[1]

				// next line contains diff line information so lets scan it here
				scanner.Scan()

				txt := scanner.Text()
				i := strings.Index(txt, diffAddPrefix)
				pairs := strings.Split(strings.Split(txt[i+1:], diffLineSignature)[0], ",")
				currStartDiffLine, err = strconv.Atoi(pairs[0])
				if err != nil {
					log.Debug(err)
					return
				}
				continue
			} else if strings.HasPrefix(txt, diffAddPrefix) && strings.Contains(txt, leak.Line) && leak.File == currFile {
				potentialLine := currLine + currStartDiffLine
				if _, ok := bundle.lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, potentialLine, currFile)]; !ok {
					bundle.lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, potentialLine, currFile)] = true
					leak.LineNumber = potentialLine
					return
				}
			} else if strings.HasPrefix(txt, diffLineSignaturePrefix) && currStartDiffLine != 0 {
				// This logic is used for when there are multiple leaks of the same offender within the same patch
				i := strings.Index(txt, diffAddPrefix)
				pairs := strings.Split(strings.Split(txt[i+1:], diffLineSignature)[0], ",")
				currStartDiffLine, err = strconv.Atoi(pairs[0])
				if err != nil {
					log.Debug(err)
					return
				}
				currLine = 0
				if !strings.HasSuffix(txt, diffLineSignature) {
					currLine = -1
				}
			}
			currLine++
		}
	case commitScan:
		if bundle.Commit == nil {
			return
		}
		f, err := bundle.Commit.File(bundle.FilePath)
		if err != nil {
			log.Error(err)
			return
		}
		r, err := f.Reader()
		if err != nil {
			log.Error(err)
			return
		}
		leak.LineNumber = extractLineHelper(r, bundle, leak)
	case uncommittedScan:
		wt, err := repo.Worktree()
		if err != nil {
			log.Error(err)
			return
		}
		f, err := wt.Filesystem.Open(leak.File)
		if err != nil {
			log.Error(err)
			return
		}
		leak.LineNumber = extractLineHelper(f, bundle, leak)
	}
}

// extractLineHelper consolidates code for checking the leak line against the contents of a reader to find the
// line number of the leak.
func extractLineHelper(r io.Reader, bundle *Bundle, leak *manager.Leak) int {
	scanner := bufio.NewScanner(r)
	lineNumber := 1
	for scanner.Scan() {
		if leak.Line == scanner.Text() {
			if _, ok := bundle.lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, bundle.FilePath)]; !ok {
				bundle.lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, bundle.FilePath)] = true
				return lineNumber
			}
		}
		lineNumber++
	}
	return -1
}

// trippedEntropy checks if a given capture group or offender falls in between entropy ranges
// supplied by a custom gitleaks configuration. Gitleaks do not check entropy by default.
func trippedEntropy(groups []string, rule config.Rule) bool {
	for _, e := range rule.Entropies {
		if len(groups) > e.Group {
			entropy := shannonEntropy(groups[e.Group])
			if entropy >= e.Min && entropy <= e.Max {
				return true
			}
		}
	}
	return false
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

// Checks if the given rule has a regex
func ruleContainRegex(rule config.Rule) bool {
	if rule.Regex == nil {
		return false
	}
	if rule.Regex.String() == "" {
		return false
	}
	return true
}

// Checks if the given rule has a file name regex
func ruleContainFileRegex(rule config.Rule) bool {
	if rule.File == nil {
		return false
	}
	if rule.File.String() == "" {
		return false
	}
	return true
}

// Checks if the given rule has a file path regex
func ruleContainPathRegex(rule config.Rule) bool {
	if rule.Path == nil {
		return false
	}
	if rule.Path.String() == "" {
		return false
	}
	return true
}

func isCommitAllowListed(commitHash string, allowlistedCommits []string) bool {
	for _, hash := range allowlistedCommits {
		if commitHash == hash {
			return true
		}
	}
	return false
}

func isAllowListed(target string, allowList []*regexp.Regexp) bool {
	if len(allowList) != 0 {
		for _, re := range allowList {
			if re.FindString(target) != "" {
				return true
			}
		}
	}
	return false

}
