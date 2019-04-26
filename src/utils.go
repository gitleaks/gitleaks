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

type pendingLeak struct {
	leak   Leak
	before int
	after  int
	wait   bool
}

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
		match       []int
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
		if rule.entropyROI == "word" {
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
		} else {
			_entropy := getShannonEntropy(line)
			for _, e := range rule.entropies {
				if _entropy > e.v1 && _entropy < e.v2 {
					entropy = _entropy
					entropyWord = line
					goto postEntropy
				}
			}
		}
	}

postEntropy:
	if rule.regex != nil && rule.regex.String() != "" {
		match = rule.regex.FindIndex([]byte(line))
	}

	if match != nil && entropy != 0.0 {
		return newLeak(line, fmt.Sprintf("%s regex match and entropy met at %.2f", rule.regex.String(), entropy), entropyWord, rule, commit, 0), nil
	} else if match != nil && rule.entropies == nil {
		return newLeak(line, fmt.Sprintf("%s regex match", rule.regex.String()), line[match[0]:match[1]], rule, commit, match[0]), nil
	} else if entropy != 0.0 && rule.regex.String() == "" {
		return newLeak(line, fmt.Sprintf("entropy met at %.2f", entropy), entropyWord, rule, commit, 0), nil
	}
	return nil, nil
}

// inspect will parse each line of the git diff's content against a set of regexes or
// a set of regexes set by the config (see gitleaks.toml for example). This function
// will skip lines that include a whitelisted regex. A list of leaks is returned.
// If verbose mode (-v/--verbose) is set, then checkDiff will log leaks as they are discovered.
func inspect(commit *commitInfo) []Leak {
	var (
		leaks   []Leak
		pLeaks  []pendingLeak
		context string
	)

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

			// Pending leaks are leaks that doesn't have their context filled (see Context option)
			if opts.Context == 0 {
				leaks = addLeak(leaks, *leak)
			} else {
				pLeaks = addPendingLeak(pLeaks, *leak)
			}
		}
		if opts.Context > 0 {
			updateContext(&context, line, &pLeaks, &leaks)
		}
	}

	// Move all pending leaks left to leaks
	for i := 0; i < len(pLeaks); i++ {
		leaks = addLeak(leaks, pLeaks[i].leak)
	}

	return leaks
}

// Context is a buffer that stores the last characters read (defined by Context option)
// The context is filled in two steps:
// 1. Context[SIZE:] + Leak (One time)
// 2. Leak + Line           (Until filled)
func updateContext(context *string, line string, pLeaks *[]pendingLeak, leaks *[]Leak) {
	// Iterate through the slice in reverse due to deletion
	for i := len(*pLeaks) - 1; i >= 0; i-- {
		if (*pLeaks)[i].after > 0 {
			if (*pLeaks)[i].wait == false {
				after := "\n" + line[:min(len(line), (*pLeaks)[i].after-1)]
				(*pLeaks)[i].leak.Line = (*pLeaks)[i].leak.Line + after
				(*pLeaks)[i].after -= len(after)
			} else {
				(*pLeaks)[i].wait = false
			}
		}

		if (*pLeaks)[i].before > 0 {
			(*pLeaks)[i].leak.Line = (*context)[max(0, len(*context)-(*pLeaks)[i].before):] + "\n" + (*pLeaks)[i].leak.Line
			(*pLeaks)[i].leak.Index = (*pLeaks)[i].leak.Index + (*pLeaks)[i].before + 1
			(*pLeaks)[i].before = 0
		}

		if (*pLeaks)[i].after <= 0 {
			*leaks = addLeak(*leaks, (*pLeaks)[i].leak)
			(*pLeaks) = append((*pLeaks)[:i], (*pLeaks)[i+1:]...)
		}
	}

	// Update Context and add break line (if necessary)
	if len(line) >= opts.Context {
		*context = line[len(line)-opts.Context:]
	} else if (len(line) + len(*context)) <= opts.Context {
		if len(*context) > 0 {
			*context = *context + "\n"
		}
		*context = *context + line
	} else {
		*context = (*context)[len(*context)-(opts.Context-len(line))+1:] + "\n" + line
	}
}

func addPendingLeak(pLeaks []pendingLeak, leak Leak) []pendingLeak {
	pLeak := pendingLeak{
		leak:   leak,
		before: opts.Context - leak.Index,
		after:  opts.Context - (len(leak.Line) - (leak.Index + len(leak.Offender))),
		wait:   true,
	}

	return append(pLeaks, pLeak)
}

func addLeak(leaks []Leak, leak Leak) []Leak {
	if opts.After != "" {
		leak.Line = leak.Line[:leak.Index+len(leak.Offender)] + opts.After + leak.Line[leak.Index+len(leak.Offender):]
	}

	if opts.Before != "" {
		leak.Line = leak.Line[:leak.Index] + opts.Before + leak.Line[leak.Index:]
	}

	if opts.Verbose {
		leak.log()
	}

	return append(leaks, leak)
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

func newLeak(line string, info string, offender string, rule *Rule, commit *commitInfo, index int) *Leak {
	if opts.Context > 0 {
		line = line[:min(len(line), index+len(offender)+opts.Context)]
		before := max(index-opts.Context, 0)
		line = line[before:]
		index = index - before
	}
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
		Index:    index,
	}
	if opts.Redact {
		leak.Offender = "REDACTED"
		leak.Line = strings.Replace(line, offender, "REDACTED", -1)
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

func max(a, b int) int {
	if a <= b {
		return b
	}
	return a
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
