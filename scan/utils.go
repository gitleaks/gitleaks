package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v7/report"

	"github.com/zricethezav/gitleaks/v7/config"
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

	maxLineLen = 200
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

func shouldLog(scanner BaseScanner) bool {
	if scanner.opts.Verbose && scanner.scannerType != typeRepoScanner &&
		scanner.scannerType != typeCommitScanner &&
		scanner.scannerType != typeUnstagedScanner &&
		scanner.scannerType != typeNoGitScanner {
		return true
	}
	return false
}

func checkRules(scanner BaseScanner, commit *object.Commit, repoName, filePath, content string) []report.Leak {
	filename := filepath.Base(filePath)
	path := filepath.Dir(filePath)
	var leaks []report.Leak

	skipRuleLookup := make(map[string]bool)
	// First do simple rule checks based on filename
	if skipCheck(scanner.cfg, filename, path) {
		return leaks
	}

	for _, rule := range scanner.cfg.Rules {
		if isCommitAllowListed(commit.Hash.String(), rule.AllowList.Commits) {
			continue
		}

		if skipRule(rule, filename, filePath, commit.Hash.String()) {
			skipRuleLookup[rule.Description] = true
			continue
		}

		// If it doesnt contain a Content regex then it is a filename regex match
		if !ruleContainRegex(rule) {
			leak := report.Leak{
				LineNumber: defaultLineNumber,
				Line:       "",
				Offender:   "Filename/path offender: " + filename,
				Commit:     commit.Hash.String(),
				Repo:       repoName,
				RepoURL:    scanner.opts.RepoURL,
				Message:    commit.Message,
				Rule:       rule.Description,
				Author:     commit.Author.Name,
				Email:      commit.Author.Email,
				Date:       commit.Author.When,
				Tags:       strings.Join(rule.Tags, ", "),
				File:       filePath,
				// Operation:  diffOpToString(bundle.Operation),
			}
			leak.LeakURL = leakURL(leak)
			if shouldLog(scanner) {
				logLeak(leak, scanner.opts.Redact)
			}
			leaks = append(leaks, leak)
		}
	}

	lineNumber := 1

	for _, line := range strings.Split(content, "\n") {
		for _, rule := range scanner.cfg.Rules {
			if isCommitAllowListed(commit.Hash.String(), rule.AllowList.Commits) {
				break
			}
			if _, ok := skipRuleLookup[rule.Description]; ok {
				continue
			}

			offender := rule.Regex.FindString(line)
			if offender == "" {
				continue
			}

			// check entropy
			groups := rule.Regex.FindStringSubmatch(offender)
			if isAllowListed(line, append(rule.AllowList.Regexes, scanner.cfg.Allowlist.Regexes...)) {
				continue
			}
			if len(rule.Entropies) != 0 && !trippedEntropy(groups, rule) {
				continue
			}

			// 0 is a match for the full regex pattern
			if 0 < rule.ReportGroup && rule.ReportGroup < len(groups) {
				offender = groups[rule.ReportGroup]
			}

			leak := report.Leak{
				LineNumber: lineNumber,
				Line:       line,
				Offender:   offender,
				Commit:     commit.Hash.String(),
				Repo:       repoName,
				RepoURL:    scanner.opts.RepoURL,
				Message:    commit.Message,
				Rule:       rule.Description,
				Author:     commit.Author.Name,
				Email:      commit.Author.Email,
				Date:       commit.Author.When,
				Tags:       strings.Join(rule.Tags, ", "),
				File:       filePath,
			}
			leak.LeakURL = leakURL(leak)
			if shouldLog(scanner) {
				logLeak(leak, scanner.opts.Redact)
			}
			leaks = append(leaks, leak)
		}
		lineNumber++
	}
	return leaks
}

func logLeak(leak report.Leak, redact bool) {
	if redact {
		leak = report.RedactLeak(leak)
	}
	var b []byte
	b, _ = json.MarshalIndent(leak, "", "	")
	fmt.Println(string(b))
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

func skipCheck(cfg config.Config, filename string, path string) bool {
	// We want to check if there is a allowlist for this file
	if len(cfg.Allowlist.Files) != 0 {
		for _, reFileName := range cfg.Allowlist.Files {
			if regexMatched(filename, reFileName) {
				log.Debugf("allowlisted file found, skipping scan of file: %s", filename)
				return true
			}
		}
	}

	// We want to check if there is a allowlist for this path
	if len(cfg.Allowlist.Paths) != 0 {
		for _, reFilePath := range cfg.Allowlist.Paths {
			if regexMatched(path, reFilePath) {
				log.Debugf("file in allowlisted path found, skipping scan of file: %s", filename)
				return true
			}
		}
	}
	return false
}

func skipRule(rule config.Rule, filename, path, commitSha string) bool {
	// For each rule we want to check filename allowlists
	if isAllowListed(filename, rule.AllowList.Files) || isAllowListed(path, rule.AllowList.Paths) {
		return true
	}

	// If it has fileNameRegex and it doesnt match we continue to next rule
	if ruleContainFileRegex(rule) && !regexMatched(filename, rule.File) {
		return true
	}

	// If it has filePathRegex and it doesnt match we continue to next rule
	if ruleContainPathRegex(rule) && !regexMatched(path, rule.Path) {
		return true
	}

	return false
}

// regexMatched matched an interface to a regular expression. The interface f can
// be a string type or go-git *object.File type.
func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
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

func optsToCommits(opts options.Options) ([]string, error) {
	if opts.Commits != "" {
		return strings.Split(opts.Commits, ","), nil
	}
	file, err := os.Open(opts.CommitsFile)
	if err != nil {
		return []string{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var commits []string
	for scanner.Scan() {
		commits = append(commits, scanner.Text())
	}
	return commits, nil
}

func extractLine(patchContent string, leak report.Leak, lineLookup map[string]bool) int {
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

func leakURL(leak report.Leak) string {
	if leak.RepoURL != "" {
		return fmt.Sprintf("%s/blob/%s/%s#L%d", leak.RepoURL, leak.Commit, leak.File, leak.LineNumber)
	}
	return ""
}
