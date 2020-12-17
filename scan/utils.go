package scan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	log "github.com/sirupsen/logrus"
)

const (
	diffAddPrefix     = "+"
	diffDelPrefix     = "-"
	diffLineSignature = " @@"
	defaultLineNumber = 1
)

func obtainCommit(repo *git.Repository, commitSha string) (*object.Commit, error) {
	if commitSha == "latest" {
		ref, err := repo.Head()
		if err != nil {
			return nil, err
		}
		commitSha = ref.Hash().String()
	}
	return repo.CommitObject(plumbing.NewHash(commitSha))
}

func getRepoName(opts options.Options) string {
	if opts.RepoURL != "" {
		return filepath.Base(opts.RepoURL)
	}
	if opts.Path != "" {
		return filepath.Base(opts.Path)
	}
	if opts.CheckUncommitted() {
		dir, _ := os.Getwd()
		return filepath.Base(dir)
	}
	return ""
}

func getRepo(opts options.Options) (*git.Repository, error) {
	if opts.OpenLocal() {
		if opts.Path != "" {
			log.Infof("opening %s\n", opts.Path)
		} else {
			log.Info("opening .")
		}
		return git.PlainOpen(opts.Path)
	}
	if opts.CheckUncommitted() {
		// open git repo from PWD
		dir, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		log.Debugf("opening %s as a repo\n", dir)
		return git.PlainOpen(dir)
	}
	return cloneRepo(opts)
}

func cloneRepo(opts options.Options) (*git.Repository, error) {
	cloneOpts, err := opts.CloneOptions()
	if err != nil {
		return nil, err
	}
	if opts.ClonePath != "" {
		log.Infof("cloning... %s to %s", cloneOpts.URL, opts.ClonePath)
		return git.PlainClone(opts.ClonePath, false, cloneOpts)
	}
	log.Infof("cloning... %s", cloneOpts.URL)
	return git.Clone(memory.NewStorage(), nil, cloneOpts)
}

// depthReached checks if i meets the depth (--depth=) if set
func depthReached(i int, opts options.Options) bool {
	if opts.Depth != 0 && opts.Depth == i {
		log.Warnf("Exceeded depth limit (%d)", i)
		return true
	}
	return false
}

// emptyCommit generates an empty commit used for scanning uncommitted changes
func emptyCommit() *object.Commit {
	return &object.Commit{
		Hash:    plumbing.Hash{},
		Message: "",
		Author: object.Signature{
			Name:  "",
			Email: "",
			When:  time.Unix(0, 0).UTC(),
		},
	}
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

// getLogOptions determines what log options are used when iterating through commits.
// It is similar to `git log {branch}`. Default behavior is to log ALL branches so
// gitleaks gets the full git history.
func logOptions(repo *git.Repository, opts options.Options) (*git.LogOptions, error) {
	var logOpts git.LogOptions
	const dateformat string = "2006-01-02"
	const timeformat string = "2006-01-02T15:04:05-0700"
	if opts.CommitFrom != "" {
		logOpts.From = plumbing.NewHash(opts.CommitFrom)
	}
	if opts.CommitSince != "" {
		if t, err := time.Parse(timeformat, opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else if t, err := time.Parse(dateformat, opts.CommitSince); err == nil {
			logOpts.Since = &t
		} else {
			return nil, err
		}
		logOpts.All = true
	}
	if opts.CommitUntil != "" {
		if t, err := time.Parse(timeformat, opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else if t, err := time.Parse(dateformat, opts.CommitUntil); err == nil {
			logOpts.Until = &t
		} else {
			return nil, err
		}
		logOpts.All = true
	}
	if opts.Branch != "" {
		ref, err := repo.Storer.Reference(plumbing.NewBranchReferenceName(opts.Branch))
		if err != nil {
			return nil, fmt.Errorf("could not find branch %s", opts.Branch)
		}
		logOpts = git.LogOptions{
			From: ref.Hash(),
		}

		if logOpts.From.IsZero() {
			return nil, fmt.Errorf("could not find branch %s", opts.Branch)
		}
		return &logOpts, nil
	}
	if !logOpts.From.IsZero() || logOpts.Since != nil || logOpts.Until != nil {
		return &logOpts, nil
	}
	return &git.LogOptions{All: true}, nil
}

func optsToCommits(opts options.Options) ([]string, error) {
	if opts.Commits != "" {
		return strings.Split(opts.Commits, ","), nil
	}
	file, err := os.Open(opts.CommitsFile)
	if err != nil {
		return []string{}, err
	}
	defer rable(file.Close)

	scanner := bufio.NewScanner(file)
	var commits []string
	for scanner.Scan() {
		commits = append(commits, scanner.Text())
	}
	return commits, nil
}

func extractLine(patchContent string, leak Leak, lineLookup map[string]bool) int {
	i := strings.Index(patchContent, fmt.Sprintf("\n+++ b/%s", leak.File))
	filePatchContent := patchContent[i+1:]
	i = strings.Index(filePatchContent, "diff --git")
	if i != -1 {
		filePatchContent = filePatchContent[:i]
	}
	chunkStartLine := 0
	currLine := 0
	for _, patchLine := range strings.Split(filePatchContent, "\n") {
		if strings.HasPrefix(patchLine, "@@") {
			i := strings.Index(patchLine, diffAddPrefix)
			pairs := strings.Split(strings.Split(patchLine[i+1:], diffLineSignature)[0], ",")
			chunkStartLine, _ = strconv.Atoi(pairs[0])
			currLine = -1
		}
		if strings.HasPrefix(patchLine, diffDelPrefix) {
			currLine--
		}
		if strings.HasPrefix(patchLine, diffAddPrefix) && strings.Contains(patchLine, leak.Line) {
			lineNumber := chunkStartLine + currLine
			if _, ok := lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, leak.File)]; !ok {
				lineLookup[fmt.Sprintf("%s%s%d%s", leak.Offender, leak.Line, lineNumber, leak.File)] = true
				return lineNumber
			}
		}
		currLine++
	}
	return defaultLineNumber
}

// rable is the second half of deferrable... mainly used for defer file.Close()
func rable(f func() error) {
	if err := f(); err != nil {
		log.Error(err)
	}
}
