package scan

import (
	"bufio"
	"fmt"
	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/v4/config"
	"github.com/zricethezav/gitleaks/v4/manager"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CheckRules accepts a file Content, fullpath of file, Commit and repo. If the file is
// binary OR if a file is matched on whitelisted files set in the configuration, then gitleaks
// will skip auditing that file. It will check first if rules apply to this file comparing filename
// and path to their respective rule regexes and inspect file Content with inspectFileContents after.
func (repo *Repo) CheckRules(frame Frame) {
	filename := filepath.Base(frame.FilePath)
	path := filepath.Dir(frame.FilePath)

	frame.lineLookup = make(map[string]bool)

	// We want to check if there is a whitelist for this file
	if len(repo.config.Whitelist.Files) != 0 {
		for _, reFileName := range repo.config.Whitelist.Files {
			if RegexMatched(filename, reFileName) {
				log.Debugf("whitelisted file found, skipping audit of file: %s", filename)
				return
			}
		}
	}

	// We want to check if there is a whitelist for this path
	if len(repo.config.Whitelist.Paths) != 0 {
		for _, reFilePath := range repo.config.Whitelist.Paths {
			if RegexMatched(path, reFilePath) {
				log.Debugf("file in whitelisted path found, skipping audit of file: %s", filename)
				return
			}
		}
	}

	for _, rule := range repo.config.Rules {
		start := time.Now()

		// For each rule we want to check filename whitelists
		if isFileNameWhiteListed(filename, rule.Whitelist) || isFilePathWhiteListed(path, rule.Whitelist) {
			continue
		}

		// If it has fileNameRegex and it doesnt match we continue to next rule
		if ruleContainFileNameRegex(rule) && !RegexMatched(filename, rule.FileNameRegex) {
			continue
		}

		// If it has filePathRegex and it doesnt match we continue to next rule
		if ruleContainFilePathRegex(rule) && !RegexMatched(path, rule.FilePathRegex) {
			continue
		}

		// If it doesnt contain a Content regex then it is a filename regex match
		if !ruleContainRegex(rule) {
			// sendLeak("Filename/path offender: "+filename, "N/A", fullpath, rule, c, repo)
			repo.Manager.SendLeaks(manager.Leak{
				Line:     "N/A",
				Offender: "Filename/path offender: " + filename,
				Commit:   frame.Commit.Hash.String(),
				Repo:     repo.Name,
				Message:  frame.Commit.Message,
				Rule:     rule.Description,
				Author:   frame.Commit.Author.Name,
				Email:    frame.Commit.Author.Email,
				Date:     frame.Commit.Author.When,
				Tags:     strings.Join(rule.Tags, ", "),
				File:     filename,
			})
		} else {
			//otherwise we check if it matches Content regex
			locs := rule.Regex.FindAllIndex([]byte(frame.Content), -1)
			if len(locs) != 0 {
				for _, loc := range locs {
					start := loc[0]
					end := loc[1]
					for start != 0 && frame.Content[start] != '\n' {
						start = start - 1
					}

					if frame.Content[start] == '\n' {
						start += 1
					}

					for end < len(frame.Content)-1 && frame.Content[end] != '\n' {
						end = end + 1
					}

					line := frame.Content[start:end]
					offender := frame.Content[loc[0]:loc[1]]
					groups := rule.Regex.FindStringSubmatch(offender)

					if isOffenderWhiteListed(offender, rule.Whitelist) {
						continue
					}

					if len(rule.Entropies) != 0 && !trippedEntropy(groups, rule) {
						continue
					}

					leak := manager.Leak{
						Line:     line,
						Offender: offender,
						Commit:   frame.Commit.Hash.String(),
						Repo:     repo.Name,
						Message:  frame.Commit.Message,
						Rule:     rule.Description,
						Author:   frame.Commit.Author.Name,
						Email:    frame.Commit.Author.Email,
						Date:     frame.Commit.Author.When,
						Tags:     strings.Join(rule.Tags, ", "),
						File:     frame.FilePath,
					}
					extractAndInjectLine(&leak, &frame)

					repo.Manager.SendLeaks(leak)
				}
			}
		}

		//	TODO should return filenameRegex if only file rule
		repo.Manager.RecordTime(manager.RegexTime{
			Time:  howLong(start),
			Regex: rule.Regex.String(),
		})
	}
}

func extractAndInjectLine(leak *manager.Leak, frame *Frame) {
	var err error
	if frame.Patch != nil {
		patch := frame.Patch.String()

		scanner := bufio.NewScanner(strings.NewReader(patch))
		currFile := ""
		currLine := 0
		currStartDiffLine := 0

		for scanner.Scan() {
			txt := scanner.Text()
			if strings.HasPrefix(txt, "+++ b") {
				currStartDiffLine = 1
				currLine = 0
				currFile = filepath.Base(strings.Split(txt, "+++ b")[1])

				// next line contains diff line information so lets scan it here
				scanner.Scan()

				txt := scanner.Text()
				i := strings.Index(txt, "+")
				pairs := strings.Split(strings.Split(txt[i+1:], " @@")[0], ",")
				currStartDiffLine, err = strconv.Atoi(pairs[0])
				if err != nil {
					log.Debug(err)
					return
				}
				continue
			} else if strings.HasPrefix(txt, "+") && strings.Contains(txt, leak.Line) && leak.File == currFile {
				potentialLine := currLine + currStartDiffLine
				if _, ok := frame.lineLookup[fmt.Sprintf("%s%d%s", leak.Line, potentialLine, currFile)]; !ok {
					frame.lineLookup[fmt.Sprintf("%s%d%s", leak.Line, potentialLine, currFile)] = true
					leak.LineNumber = potentialLine
					return
				}
			}
			currLine++
		}
	}
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

// getShannonEntropy https://en.wiktionary.org/wiki/Shannon_entropy
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
func ruleContainFileNameRegex(rule config.Rule) bool {
	if rule.FileNameRegex == nil {
		return false
	}
	if rule.FileNameRegex.String() == "" {
		return false
	}
	return true
}

// Checks if the given rule has a file path regex
func ruleContainFilePathRegex(rule config.Rule) bool {
	if rule.FilePathRegex == nil {
		return false
	}
	if rule.FilePathRegex.String() == "" {
		return false
	}
	return true
}

func isCommitWhiteListed(commitHash string, whitelistedCommits []string) bool {
	for _, hash := range whitelistedCommits {
		if commitHash == hash {
			return true
		}
	}
	return false
}

func isOffenderWhiteListed(offender string, whitelist []config.Whitelist) bool {
	if len(whitelist) != 0 {
		for _, wl := range whitelist {
			if wl.Regex.FindString(offender) != "" {
				return true
			}
		}
	}
	return false
}

func isFileNameWhiteListed(filename string, whitelist []config.Whitelist) bool {
	if len(whitelist) != 0 {
		for _, wl := range whitelist {
			if RegexMatched(filename, wl.File) {
				return true
			}
		}
	}
	return false
}

func isFilePathWhiteListed(filepath string, whitelist []config.Whitelist) bool {
	if len(whitelist) != 0 {
		for _, wl := range whitelist {
			if RegexMatched(filepath, wl.Path) {
				return true
			}
		}
	}
	return false
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
