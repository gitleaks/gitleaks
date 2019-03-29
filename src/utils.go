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
		w.Write([]string{"repo", "line", "commit", "offender", "reason", "commitMsg", "author", "file", "date"})
		for _, leak := range leaks {
			w.Write([]string{leak.Repo, leak.Line, leak.Commit, leak.Offender, leak.Type, leak.Message, leak.Author, leak.File, leak.Date.Format(time.RFC3339)})
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

// inspect will parse each line of the git diff's content against a set of regexes or
// a set of regexes set by the config (see gitleaks.toml for example). This function
// will skip lines that include a whitelisted regex. A list of leaks is returned.
// If verbose mode (-v/--verbose) is set, then checkDiff will log leaks as they are discovered.
func inspect(commit commitInfo) []Leak {
	var (
		leaks    []Leak
		skipLine bool
	)
	lines := strings.Split(commit.content, "\n")

	for _, line := range lines {
		skipLine = false
		for _, re := range config.Regexes {
			match := re.regex.FindString(line)
			if match == "" {
				continue
			}
			if skipLine = isLineWhitelisted(line); skipLine {
				break
			}
			leaks = addLeak(leaks, line, match, re.description, commit)
		}

		if !skipLine && (opts.Entropy > 0 || len(config.Entropy.entropyRanges) != 0) {
			words := strings.Fields(line)
			for _, word := range words {
				entropy := getShannonEntropy(word)
				// Only check entropyRegexes and whiteListRegexes once per line, and only if an entropy leak type
				// was found above, since regex checks are expensive.
				if !entropyIsHighEnough(entropy) {
					continue
				}
				// If either the line is whitelisted or the line fails the noiseReduction check (when enabled),
				// then we can skip checking the rest of the line for high entropy words.
				if skipLine = !highEntropyLineIsALeak(line) || isLineWhitelisted(line); skipLine {
					break
				}
				leaks = addLeak(leaks, line, word, fmt.Sprintf("Entropy: %.2f", entropy), commit)
			}
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

// addLeak is helper for func inspect() to append leaks if found during a diff check.
func addLeak(leaks []Leak, line string, offender string, leakType string, commit commitInfo) []Leak {
	leak := Leak{
		Line:     line,
		Commit:   commit.sha,
		Offender: offender,
		Type:     leakType,
		Author:   commit.author,
		File:     commit.filePath,
		Repo:     commit.repoName,
		Message:  commit.message,
		Date:     commit.date,
	}
	if opts.Redact {
		leak.Offender = "REDACTED"
		leak.Line = strings.Replace(line, offender, "REDACTED", -1)
	}

	if opts.Verbose {
		leak.log()
	}

	leaks = append(leaks, leak)
	return leaks
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
