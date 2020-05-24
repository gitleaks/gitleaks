package audit

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v4/config"
	"github.com/zricethezav/gitleaks/v4/manager"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	fdiff "github.com/go-git/go-git/v5/plumbing/format/diff"
	"github.com/go-git/go-git/v5/plumbing/object"
	log "github.com/sirupsen/logrus"
)

// Inspect patch accepts a patch, commit, and repo. If the patches contains files that are
// binary, then gitleaks will skip auditing that file OR if a file is matched on
// whitelisted files set in the configuration. If a global rule for files is defined and a filename
// matches said global rule, then a leak is sent to the manager.
// After that, file chunks are created which are then inspected by InspectString()
func inspectPatch(patch *object.Patch, c *object.Commit, repo *Repo) {
	for _, f := range patch.FilePatches() {
		if repo.timeoutReached() {
			return
		}
		if f.IsBinary() {
			continue
		}
		for _, chunk := range f.Chunks() {
			if chunk.Type() == fdiff.Delete || chunk.Type() == fdiff.Add {
				InspectFile(chunk.Content(), getFileFullPath(f), c, repo)
			}
		}
	}
}

// getFileName accepts a file patch and returns the filename
func getFileFullPath(f fdiff.FilePatch) string {
	fn := "???"
	from, to := f.Files()
	if from != nil {
		return from.Path()
	} else if to != nil {
		return to.Path()
	}

	return fn
}

// getFileName accepts a string with full path and returns only path
func getFilePath(fullpath string) string {
	return filepath.Dir(fullpath)
}

// getFileName accepts a string with full path and returns only filename
func getFileName(fullpath string) string {
	return filepath.Base(fullpath)
}

// aws_access_key_id='AKIAIO5FODNN7EXAMPLE',
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

func sendLeak(offender string, line string, filename string, rule config.Rule, c *object.Commit, repo *Repo) {
	repo.Manager.SendLeaks(manager.Leak{
		Line:     line,
		Offender: offender,
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

// InspectFile accepts a file content, fullpath of file, commit and repo. If the file is
// binary OR if a file is matched on whitelisted files set in the configuration, then gitleaks
// will skip auditing that file. It will check first if rules apply to this file comparing filename
// and path to their respective rule regexes and inspect file content with inspectFileContents after.
func InspectFile(content string, fullpath string, c *object.Commit, repo *Repo) {

	filename := getFileName(fullpath)
	path := getFilePath(fullpath)

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

		// If it doesnt contain a content regex then it is a filename regex match
		if !ruleContainRegex(rule) {
			sendLeak("Filename/path offender: "+filename, "N/A", fullpath, rule, c, repo)
		} else {
			//otherwise we check if it matches content regex
			inspectFileContents(content, fullpath, rule, c, repo)
		}

		//	TODO should return filenameRegex if only file rule
		repo.Manager.RecordTime(manager.RegexTime{
			Time:  howLong(start),
			Regex: rule.Regex.String(),
		})
	}
}

// InspectString accepts a string, commit object, repo, and filename. This function iterates over
// all the rules set by the gitleaks config. If the rule contains entropy checks then entropy will be checked first.
// Next, if the rule contains a regular expression then that will be checked.
func inspectFileContents(content string, path string, rule config.Rule, c *object.Commit, repo *Repo) {
	locs := rule.Regex.FindAllIndex([]byte(content), -1)
	if len(locs) != 0 {
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

			line := content[start:end]
			offender := content[loc[0]:loc[1]]
			groups := rule.Regex.FindStringSubmatch(offender)

			if isOffenderWhiteListed(offender, rule.Whitelist) {
				continue
			}

			if len(rule.Entropies) != 0 && !trippedEntropy(groups, rule) {
				continue
			}

			sendLeak(offender, line, path, rule, c, repo)
		}
	}
}

type commitInspector func(c *object.Commit, repo *Repo) error

// inspectCommit accepts a commit hash, repo, and commit inspecting function. A new commit
// object will be created from the hash which will be passed into either inspectCommitPatches
// or inspectFilesAtCommit depending on the options set.
func inspectCommit(commit string, repo *Repo, f commitInspector) error {
	if commit == "latest" {
		ref, err := repo.Repository.Head()
		if err != nil {
			return err
		}
		commit = ref.Hash().String()
	}
	repo.Manager.IncrementCommits(1)
	h := plumbing.NewHash(commit)
	c, err := repo.CommitObject(h)
	if err != nil {
		return err
	}
	return f(c, repo)
}

// inspectCommitPatches accepts a commit object and a repo. This function is only called when the --commit=
// option has been set. That option tells gitleaks to look only at a single commit and check the contents
// of said commit. Similar to inspectPatch(), if the files contained in the commit are a binaries or if they are
// whitelisted then those files will be skipped.
func inspectCommitPatches(c *object.Commit, repo *Repo) error {
	if len(c.ParentHashes) == 0 {
		err := inspectFilesAtCommit(c, repo)
		if err != nil {
			return err
		}
	}

	return c.Parents().ForEach(func(parent *object.Commit) error {
		defer func() {
			if err := recover(); err != nil {
				// sometimes the patch generation will fail due to a known bug in
				// sergi's go-diff: https://github.com/sergi/go-diff/issues/89.
				// Once a fix has been merged I will remove this recover.
				return
			}
		}()
		if repo.timeoutReached() {
			return nil
		}
		start := time.Now()
		patch, err := c.Patch(parent)
		if err != nil {
			return fmt.Errorf("could not generate patch")
		}
		repo.Manager.RecordTime(manager.PatchTime(howLong(start)))
		inspectPatch(patch, c, repo)
		return nil
	})
}

// inspectFilesAtCommit accepts a commit object and a repo. This function is only called when the --files-at-commit=
// option has been set. That option tells gitleaks to look only at ALL the files at a commit and check the contents
// of said commit. Similar to inspectPatch(), if the files contained in the commit are a binaries or if they are
// whitelisted then those files will be skipped.
func inspectFilesAtCommit(c *object.Commit, repo *Repo) error {
	fIter, err := c.Files()
	if err != nil {
		return err
	}

	err = fIter.ForEach(func(f *object.File) error {
		bin, err := f.IsBinary()
		if bin || repo.timeoutReached() {
			return nil
		} else if err != nil {
			return err
		}

		content, err := f.Contents()
		if err != nil {
			return err
		}

		InspectFile(content, f.Name, c, repo)

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

// getLogOptions determines what log options are used when iterating through commits.
// It is similar to `git log {branch}`. Default behavior is to log ALL branches so
// gitleaks gets the full git history.
func getLogOptions(repo *Repo) (*git.LogOptions, error) {
	var logOpts git.LogOptions
	const dateformat string = "2006-01-02"
	const timeformat string = "2006-01-02T15:04:05-0700"
	if repo.Manager.Opts.CommitFrom != "" {
		logOpts.From = plumbing.NewHash(repo.Manager.Opts.CommitFrom)
	}
	if repo.Manager.Opts.CommitSince != "" {
		if t, err := time.Parse(timeformat, repo.Manager.Opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else if t, err := time.Parse(dateformat, repo.Manager.Opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else {
			return nil, err
		}
	}
	if repo.Manager.Opts.CommitUntil != "" {
		if t, err := time.Parse(timeformat, repo.Manager.Opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else if t, err := time.Parse(dateformat, repo.Manager.Opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else {
			return nil, err
		}
	}
	if repo.Manager.Opts.Branch != "" {
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
	if !logOpts.From.IsZero() || logOpts.Since != nil || logOpts.Until != nil {
		return &logOpts, nil
	}
	return &git.LogOptions{All: true}, nil
}

// howLong accepts a time.Time object which is subtracted from time.Now() and
// converted to nanoseconds which is returned
func howLong(t time.Time) int64 {
	return time.Now().Sub(t).Nanoseconds()
}
