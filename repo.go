package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"path"
)

type Repo struct {
	name   string
	url    string
	path   string
	status string // TODO
	leaks  []Leak
}

type Leak struct {
	Line     string `json:"line"`
	Commit   string `json:"commit"`
	Offender string `json:"string"`
	Reason   string `json:"reason"`
	Msg      string `json:"commitMsg"`
	Time     string `json:"time"`
	Author   string `json:"author"`
	File     string `json:"file"`
	RepoURL  string `json:"repoURL"`
}

type Commit struct {
	Hash   string
	Author string
	Time   string
	Msg    string
}

// running gitleaks on local repo
func newLocalRepo(repoPath string) *Repo {
	_, name := path.Split(repoPath)
	repo := &Repo{
		name: name,
		path: repoPath,
	}
	return repo

}

func newRepo(name string, url string) *Repo {
	repo := &Repo{
		name:  name,
		url:   url,
		// TODO handle existing one
		path:  opts.ClonePath + "/" + name,
	}
	return repo
}

func (repo *Repo) rLog(msg string) {
	// logger should have these infos: msg, repo, owner, time
	logger.Debug("Beginning audit",
		zap.String("repo", repo.name),
		zap.String("repo_path", repo.path),
	)
}

// Audit operates on a single repo and searches the full or partial history of the repo.
// A semaphore is declared for every repo to bind concurrency. If unbounded, the system will throw a
// `too many open files` error. Eventually, gitleaks should use src-d/go-git to avoid shelling out
// commands so that users could opt for doing all clones/diffs in memory.
// Audit also declares two WaitGroups, one for distributing regex/entropy checks, and one for receiving
// the leaks if there are any. This could be done a little more elegantly in the future.
func (repo *Repo) audit(owner *Owner) (bool, error) {
	var (
		out               []byte
		err               error
		commitWG          sync.WaitGroup
		gitLeakReceiverWG sync.WaitGroup
		gitLeaksChan      = make(chan Leak)
		leaks             []Leak
		semaphoreChan     = make(chan struct{}, opts.Concurrency)
		leaksPst 		  bool
	)

	dotGitPath := filepath.Join(repo.path, ".git")

	// Navigate to proper location to being audit. Clone repo
	// if not present, otherwise fetch for new changes.
	if _, err := os.Stat(dotGitPath); os.IsNotExist(err) {
		if opts.LocalMode {
			return false, fmt.Errorf("%s does not exist", repo.path)
		}
		// no repo present, clone it
		fmt.Printf("Cloning \x1b[37;1m%s\x1b[0m into %s...\n", repo.url, repo.path)
		err = exec.Command("git", "clone", repo.url, repo.path).Run()
		if err != nil {
			return false, fmt.Errorf("cannot clone %s into %s", repo.url, repo.path)
		}
	} else {
		fmt.Printf("Checking \x1b[37;1m%s\x1b[0m from %s...\n", repo.url, repo.path)
		err = exec.Command("git", "fetch").Run()
		if err != nil {
			return false, fmt.Errorf("cannot fetch %s from %s", repo.url, repo.path)
		}
	}

	err = os.Chdir(fmt.Sprintf(repo.path))
	if err != nil {
		return false, fmt.Errorf("cannot navigate to %s", repo.path)
	}

	gitFormat := "--format=%H%n%an%n%s%n%ci"
	out, err = exec.Command("git", "rev-list", "--all",
		"--remotes", "--topo-order", gitFormat).Output()

	if err != nil {
		return false, fmt.Errorf("could not retreive rev-list from %s", repo.name)
	}

	revListLines := bytes.Split(out, []byte("\n"))
	commits := parseRevList(revListLines)

	for _, commit := range commits {
		if commit.Hash == "" {
			continue
		}

		commitWG.Add(1)
		go auditDiff(commit, repo, &commitWG, &gitLeakReceiverWG,
			semaphoreChan, gitLeaksChan)

		if commit.Hash == opts.SinceCommit {
			break
		}
	}
	go reportAggregator(&gitLeakReceiverWG, gitLeaksChan, &leaks)
	commitWG.Wait()
	gitLeakReceiverWG.Wait()
	if len(leaks) != 0{
		leaksPst = true
	}

	if opts.ReportPath != "" && len(leaks) != 0 {
		err = repo.writeReport()
		if err != nil {
			return leaksPst, fmt.Errorf("could not write report to %s", opts.ReportPath)
		}
	}
	return leaksPst, nil
}

// Used by audit, writeReport will generate a report and write it out to
// $GITLEAKS_HOME/report/<owner>/<repo>. No report will be generated if
// no leaks have been found
func (repo *Repo) writeReport() error {
	reportJSON, _ := json.MarshalIndent(repo.leaks, "", "\t")

	if _, err := os.Stat(opts.ReportPath); os.IsNotExist(err) {
		os.Mkdir(opts.ReportPath, os.ModePerm)
	}

	reportFileName := fmt.Sprintf("%s_leaks.json", repo.name)
	reportFile := filepath.Join(opts.ReportPath, reportFileName)
	err := ioutil.WriteFile(reportFile, reportJSON, 0644)
	if err != nil {
		return err
	}
	fmt.Printf("Report written to %s\n", reportFile)
	return nil
}

// parseRevList is responsible for parsing the output of
// $ `git rev-list --all -remotes --topo-order --format=%H%n%an%n%s%n%ci`
// sample output from the above command looks like:
//		...
// 		SHA
// 		Author Name
// 		Commit Msg
// 		Commit Date
//		...
// Used by audit
func parseRevList(revList [][]byte) []Commit {
	var commits []Commit
	for i := 0; i < len(revList)-1; i = i + 5 {
		commit := Commit{
			Hash:   string(revList[i+1]),
			Author: string(revList[i+2]),
			Msg:    string(revList[i+3]),
			Time:   string(revList[i+4]),
		}
		commits = append(commits, commit)
	}
	return commits
}

// reportAggregator is a go func responsible for ...
func reportAggregator(gitLeakReceiverWG *sync.WaitGroup, gitLeaks chan Leak, leaks *[]Leak) {
	for gitLeak := range gitLeaks {
		b, err := json.MarshalIndent(gitLeak, "", "   ")
		if err != nil {
			// make waitgroup errArray
			fmt.Println("failed to output leak:", err)
		}
		fmt.Println(string(b))
		*leaks = append(*leaks, gitLeak)
		gitLeakReceiverWG.Done()
	}
}

// Used by audit, auditDiff is a go func responsible for diffing and auditing a commit.
// Three channels are input here: 1. a semaphore to bind gitleaks, 2. a leak stream, 3. error handling (TODO)
// This func performs a diff and runs regexes checks on each line of the diff.
func auditDiff(currCommit Commit, repo *Repo, commitWG *sync.WaitGroup,
	gitLeakReceiverWG *sync.WaitGroup, semaphoreChan chan struct{},
	gitLeaks chan Leak) {
	// signal to WG this diff is done being audited
	defer commitWG.Done()

	if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
		// TODO handle this better
		os.Exit(EXIT_FAILURE)
	}

	commitCmp := fmt.Sprintf("%s^!", currCommit.Hash)
	semaphoreChan <- struct{}{}
	out, err := exec.Command("git", "diff", commitCmp).Output()
	<-semaphoreChan

	if err != nil {
		os.Exit(EXIT_FAILURE)
	}

	leaks := doChecks(string(out), currCommit, repo)
	if len(leaks) == 0 {
		return
	}
	for _, leak := range leaks {
		gitLeakReceiverWG.Add(1)
		gitLeaks <- leak
	}
}
