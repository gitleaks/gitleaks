package audit

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/config"
	"github.com/zricethezav/gitleaks/manager"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	fdiff "gopkg.in/src-d/go-git.v4/plumbing/format/diff"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"math"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const maxLineLen = 200

// Inspect patch accepts a patch, commit, and repo. If the patches contains files that are
// binary, then gitleaks will skip auditing that file OR if a file is matched on
// whitelisted files set in the configuration. If a global rule for files is defined and a filename
// matches said global rule, then a laek is sent to the manager.
// After that, file chunks are created which are then inspected by InspectString()
func inspectPatch(patch *object.Patch, c *object.Commit, repo *Repo) {
	for _, f := range patch.FilePatches() {
		if f.IsBinary() {
			continue
		}
		if fileMatched(getFileName(f), repo.config.Whitelist.File) {
			log.Debugf("whitelisted file found, skipping audit of file: %s", getFileName(f))
			continue
		}
		if fileMatched(getFileName(f), repo.config.FileRegex) {
			repo.Manager.SendLeaks(manager.Leak{
				Line:     "N/A",
				Offender: getFileName(f),
				Commit:   c.Hash.String(),
				Repo:     repo.Name,
				Rule:     "file regex matched" + repo.config.FileRegex.String(),
				Author:   c.Author.Name,
				Email:    c.Author.Email,
				Date:     c.Author.When,
				File:     getFileName(f),
			})
		}
		for _, chunk := range f.Chunks() {
			if chunk.Type() == fdiff.Delete || chunk.Type() == fdiff.Add {
				InspectString(chunk.Content(), c, repo, getFileName(f))
			}
		}
	}
}

// getFileName accepts a file patch and returns the filename
func getFileName(f fdiff.FilePatch) string {
	fn := "???"
	from, to := f.Files()
	if from != nil {
		return path.Base(from.Path())
	} else if to != nil {
		return path.Base(to.Path())
	}

	return fn
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

// trippedEntropy checks if a given line falls in between entropy ranges supplied
// by a custom gitleaks configuration. Gitleaks do not check entropy by default.
func trippedEntropy(line string, rule config.Rule) bool {
	for _, e := range rule.Entropy {
		entropy := shannonEntropy(line)
		if entropy > e.P1 && entropy < e.P2 {
			return true
		}
	}
	return false
}

// InspectString accepts a string, commit object, repo, and filename. This function iterates over
// all the rules set by the gitleaks config. If the rule contains entropy checks then entropy will be checked first.
// Next, if the rule contains a regular expression then that will be checked.
func InspectString(content string, c *object.Commit, repo *Repo, filename string) {
	for _, rule := range repo.config.Rules {
		// check entropy
		if len(rule.Entropy) != 0 {
			// TODO
			// an optimization would be to switch the regex from FindAllIndex to FindString
			// since we are iterating on the lines if entropy rules exist...
			for _, line := range strings.Split(content, "\n") {
				if trippedEntropy(line, rule) {
					_line := line
					if len(_line) > maxLineLen {
						_line = line[0 : maxLineLen-1]
					}
					repo.Manager.SendLeaks(manager.Leak{
						Line:     _line,
						Offender: fmt.Sprintf("Entropy range %+v", rule.Entropy),
						Commit:   c.Hash.String(),
						Repo:     repo.Name,
						Message:  c.Message,
						Rule:     rule.Description,
						Author:   c.Author.Name,
						Email:    c.Author.Email,
						Date:     c.Author.When,
						Tags:     strings.Join(rule.Tags, ", "),
						File:     filename,
					})
				}
			}
		}
		if rule.Regex.String() == "" {
			continue
		}
		start := time.Now()
		locs := rule.Regex.FindAllIndex([]byte(content), -1)
		if len(locs) != 0 {
			// check if any rules are whitelisting this leak
			if len(rule.Whitelist) != 0 {
				for _, wl := range rule.Whitelist {
					if fileMatched(filename, wl.File) {
						// if matched, go to next rule
						goto NEXT
					}
				}
			}
			for _, loc := range locs {
				start := loc[0]
				end := loc[1]
				for start != 0 && content[start] != '\n' {
					start = start - 1
				}
				if start != 0 {
					// skip newline
					start = start + 1
				}

				for end < len(content)-1 && content[end] != '\n' {
					end = end + 1
				}

				offender := content[loc[0]:loc[1]]
				line := content[start:end]
				if repo.Manager.Opts.Redact {
					line = strings.ReplaceAll(line, offender, "REDACTED")
					offender = "REDACTED"
				}

				repo.Manager.SendLeaks(manager.Leak{
					Line:     line,
					Offender: offender,
					Commit:   c.Hash.String(),
					Message:  c.Message,
					Repo:     repo.Name,
					Rule:     rule.Description,
					Author:   c.Author.Name,
					Email:    c.Author.Email,
					Date:     c.Author.When,
					Tags:     strings.Join(rule.Tags, ", "),
					File:     filename,
				})
			}
		}
		repo.Manager.RecordTime(manager.RegexTime{
			Time:  time.Now().Sub(start).Nanoseconds(),
			Regex: rule.Regex.String(),
		})
	NEXT:
	}
}

// inspectCommit accepts a commit object and a repo. This function is only called when the --commit=
// option has been set. That option tells gitleaks to look only at a single commit and check the contents
// of said commit. Similar to inspectPatch(), if the files contained in the commit are a binaries or if they are
// whitelisted then those files will be skipped.
func inspectCommit(c *object.Commit, repo *Repo) error {
	fIter, err := c.Files()
	if err != nil {
		return err
	}

	err = fIter.ForEach(func(f *object.File) error {
		bin, err := f.IsBinary()
		if bin {
			return nil
		} else if err != nil {
			return err
		}
		if fileMatched(f, repo.config.Whitelist.File) {
			log.Debugf("whitelisted file found, skipping audit of file: %s", f.Name)
			return nil
		}
		content, err := f.Contents()
		if err != nil {
			return err
		}

		InspectString(content, c, repo, f.Name)

		return nil
	})
	return err
}

// howManyThreads will return a number 1-GOMAXPROCS which is the number
// of goroutines that will spawn during gitleaks execution
func howManyThreads(threads int) int {
	maxThreads := runtime.GOMAXPROCS(0)
	if threads == 0 {
		return 1
	} else if threads > maxThreads {
		log.Warnf("%d threads set too high, setting to system max, %d", threads, maxThreads)
		return maxThreads
	}
	return threads
}

func isCommitWhiteListed(commitHash string, whitelistedCommits []string) bool {
	for _, hash := range whitelistedCommits {
		if commitHash == hash {
			return true
		}
	}
	return false
}

func fileMatched(f interface{}, re *regexp.Regexp) bool {
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

// getLogOptions determines what log options are used when iterating through commits.
// It is similar to `git log {branch}`. Default behavior is to log ALL branches so
// gitleaks gets the full git history.
func getLogOptions(repo *Repo) (*git.LogOptions, error) {
	if repo.Manager.Opts.Branch != "" {
		var logOpts git.LogOptions
		refs, err := repo.Storer.IterReferences()
		if err != nil {
			return nil, err
		}
		err = refs.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().IsTag() {
				return nil
			}
			// check heads first
			if ref.Name().String() == "refs/heads/"+repo.Manager.Opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			} else if ref.Name().String() == "refs/remotes/origin/"+repo.Manager.Opts.Branch {
				logOpts = git.LogOptions{
					From: ref.Hash(),
				}
				return nil
			}
			return nil
		})
		if logOpts.From.IsZero() {
			return nil, fmt.Errorf("could not find branch %s", repo.Manager.Opts.Branch)
		}
		return &logOpts, nil
	}
	return &git.LogOptions{All: true}, nil
}

// howLong accepts a time.Time object which is subtracted from time.Now() and
// converted to nanoseconds which is returned
func howLong(t time.Time) int64 {
	return time.Now().Sub(t).Nanoseconds()
}
