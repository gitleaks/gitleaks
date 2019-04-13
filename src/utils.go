package gitleaks

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
)

type commitInfo struct {
	content  string
	commit   *object.Commit
	filePath string
	repoName string
	sha      string
	message  string
	author   string
	email    string
	date     time.Time
}

// writeReport writes a report to a file specified in the --report= option.
// Default format for report is JSON. You can use the --csv option to write the report as a csv
func writeReport(leaks []Leak) error {
	if len(leaks) == 0 {
		return nil
	}

	log.Infof("writing report to %s", opts.Report)
	if strings.HasSuffix(opts.Report, ".csv") {
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		w := csv.NewWriter(f)
		w.Write([]string{"repo", "line", "commit", "offender", "rule", "info", "tags", "severity", "commitMsg", "author", "email", "file", "date"})
		for _, leak := range leaks {
			w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Rule, leak.Info, leak.Tags, leak.Severity, leak.Message, leak.Author, leak.Email, leak.File, leak.Date.Format(time.RFC3339)})
		}
		w.Flush()
	} else {
		f, err := os.Create(opts.Report)
		if err != nil {
			return err
		}
		defer f.Close()
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "\t")
		if _, err := f.WriteString("[\n"); err != nil {
			return err
		}
		for i := 0; i < len(leaks); i++ {
			if err := encoder.Encode(leaks[i]); err != nil {
				return err
			}
			// for all but the last leak, seek back and overwrite the newline appended by Encode() with comma & newline
			if i+1 < len(leaks) {
				if _, err := f.Seek(-1, 1); err != nil {
					return err
				}
				if _, err := f.WriteString(",\n"); err != nil {
					return err
				}
			}
		}
		if _, err := f.WriteString("]"); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			log.Error(err)
			return err
		}
	}
	return nil
}

// check rule will inspect a single line and return a leak if it encounters one
func (rule *Rule) check(line string, commit *commitInfo) (*Leak, error) {
	var (
		match       string
		fileMatch   string
		entropy     float64
		entropyWord string
	)

	for _, f := range rule.fileTypes {
		fileMatch = f.FindString(commit.filePath)
		if fileMatch != "" {
			break
		}
	}

	if fileMatch == "" && len(rule.fileTypes) != 0 {
		return nil, nil
	}

	if rule.entropies != nil {
		if rule.entropyROI == "line" {
			_entropy := getShannonEntropy(line)
			for _, e := range rule.entropies {
				if _entropy > e.v1 && _entropy < e.v2 {
					entropy = _entropy
					entropyWord = line
					goto postEntropy
				}
			}
		} else {
			words := strings.Fields(line)
			for _, word := range words {
				_entropy := getShannonEntropy(word)
				for _, e := range rule.entropies {
					if _entropy > e.v1 && _entropy < e.v2 {
						entropy = _entropy
						entropyWord = word
						goto postEntropy
					}
				}
			}
		}
	}

postEntropy:
	if rule.regex != nil {
		match = rule.regex.FindString(line)
	}

	if match != "" && entropy != 0.0 {
		return newLeak(line, fmt.Sprintf("%s regex match and entropy met at %.2f", rule.regex.String(), entropy), entropyWord, rule, commit), nil
	} else if match != "" && rule.entropies == nil {
		return newLeak(line, fmt.Sprintf("%s regex match", rule.regex.String()), match, rule, commit), nil
	} else if entropy != 0.0 && rule.regex.String() == "" {
		return newLeak(line, fmt.Sprintf("entropy met at %.2f", entropy), entropyWord, rule, commit), nil
	}
	return nil, nil
}

// inspect will parse each line of the git diff's content against a set of regexes or
// a set of regexes set by the config (see gitleaks.toml for example). This function
// will skip lines that include a whitelisted regex. A list of leaks is returned.
// If verbose mode (-v/--verbose) is set, then checkDiff will log leaks as they are discovered.
func inspect(commit *commitInfo) []Leak {
	var leaks []Leak
	lines := strings.Split(commit.content, "\n")

	for _, line := range lines {
		for _, rule := range config.Rules {
			if isLineWhitelisted(line) {
				break
			}
			leak, err := rule.check(line, commit)
			if err != nil || leak == nil {
				continue
			}
			leaks = append(leaks, *leak)
		}
	}
	return leaks
}

// isLineWhitelisted returns true iff the line is matched by at least one of the whiteListRegexes.
func isLineWhitelisted(line string) bool {
	for _, wRe := range config.WhiteList.regexes {
		whitelistMatch := wRe.FindString(line)
		if whitelistMatch != "" {
			return true
		}
	}
	return false
}

func newLeak(line string, info string, offender string, rule *Rule, commit *commitInfo) *Leak {
	leak := &Leak{
		Line:     line,
		Commit:   commit.sha,
		Offender: offender,
		Rule:     rule.description,
		Info:     info,
		Author:   commit.author,
		Email:    commit.email,
		File:     commit.filePath,
		Repo:     commit.repoName,
		Message:  commit.message,
		Date:     commit.date,
		Tags:     strings.Join(rule.tags, ", "),
		Severity: rule.severity,
	}
	if opts.Redact {
		leak.Offender = "REDACTED"
		leak.Line = strings.Replace(line, offender, "REDACTED", -1)
	}

	if opts.Verbose {
		leak.log()
	}
	return leak
}

// discoverRepos walks all the children of `path`. If a child directory
// contain a .git subdirectory then that repo will be added to the list of repos returned
func discoverRepos(ownerPath string) ([]*RepoInfo, error) {
	var (
		err    error
		repoDs []*RepoInfo
	)
	files, err := ioutil.ReadDir(ownerPath)
	if err != nil {
		return repoDs, err
	}
	for _, f := range files {
		repoPath := path.Join(ownerPath, f.Name())
		if f.IsDir() && containsGit(repoPath) {
			repoDs = append(repoDs, &RepoInfo{
				name: f.Name(),
				path: repoPath,
			})
		}
	}
	return repoDs, err
}

func (leak Leak) log() {
	b, _ := json.MarshalIndent(leak, "", "   ")
	fmt.Println(string(b))
}

func containsGit(repoPath string) bool {
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		return false
	}
	return true
}
