package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"strings"
)

// LeakElem contains the line and commit of a leak
type LeakElem struct {
	Line     string `json:"line"`
	Commit   string `json:"commit"`
	Offender string `json:"string"`
	Reason   string `json:"reason"`
	Msg 	 string `json:"commitMsg"`
	Time 	 string `json:"time"`
	Author   string `json:"author"`
	File     string `json:"file"`
	RepoURL  string `json:"repoURL"`
}

type Commit struct {
	Hash string
	Author string
	Time string
	Msg string
}

func rmTmp(owner *Owner){
	if _, err := os.Stat(owner.path); err == nil {
		err := os.RemoveAll(owner.path)
		log.Printf("Cleaning up tmp repos in %s\n", owner.path)
		if err != nil {
			log.Printf("failed to properly remove tmp gitleaks dir: %v", err)
		}
	}
	os.Exit(1)
}

// start
func start(repos []RepoDesc, owner *Owner, opts *Options) {
	var report []LeakElem
	if opts.Tmp{
		defer rmTmp(owner)
	}

	// interrupt handling
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if opts.Tmp {
			rmTmp(owner)
		}
		os.Exit(1)
	}()

	// run checks on repos
	for _, repo := range repos {
		dotGitPath := filepath.Join(repo.path, ".git")
		if _, err := os.Stat(dotGitPath); err == nil {
			if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
				log.Fatal(err)
			}
			// use pre-cloned repo
			fmt.Printf("Checking \x1b[37;1m%s\x1b[0m...\n", repo.url)
			err := exec.Command("git", "fetch").Run()
			if err != nil {
				log.Printf("failed to fetch repo %v", err)
				return
			}
			report = getLeaks(repo, owner, opts)
		} else {
			// no repo present, clone it
			if err := os.Chdir(fmt.Sprintf(owner.path)); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Cloning \x1b[37;1m%s\x1b[0m...\n", repo.url)
			err := exec.Command("git", "clone", repo.url).Run()
			if err != nil {
				log.Printf("failed to clone repo %v", err)
				return
			}
			report = getLeaks(repo, owner, opts)
		}

		if len(report) == 0 {
			fmt.Printf("No Leaks detected for \x1b[35;2m%s\x1b[0m...\n\n", repo.url)
		}

		if opts.EnableJSON {
			outputGitLeaksReport(report, repo, opts)
		}
	}
}

// outputGitLeaksReport
func outputGitLeaksReport(report []LeakElem, repo RepoDesc, opts *Options) {
	reportJSON, _ := json.MarshalIndent(report, "", "\t")
	if _, err := os.Stat(repo.owner.reportPath); os.IsNotExist(err) {
		os.Mkdir(repo.owner.reportPath, os.ModePerm)
	}

	reportFileName := fmt.Sprintf("%s_leaks.json", repo.name)
	reportFile := filepath.Join(repo.owner.reportPath, reportFileName)
	err := ioutil.WriteFile(reportFile, reportJSON, 0644)
	if err != nil {
		log.Fatalf("Can't write to file: %s", err)
	}
}

// getLeaks will attempt to find gitleaks
func getLeaks(repo RepoDesc, owner *Owner, opts *Options) []LeakElem {
	var (
		out               []byte
		err               error
		commitWG          sync.WaitGroup
		gitLeakReceiverWG sync.WaitGroup
		gitLeaks          = make(chan LeakElem)
		report            []LeakElem
	)
	semaphoreChan := make(chan struct{}, opts.Concurrency)
	if opts.Tmp{
		defer rmTmp(owner)
	}

	go func(commitWG *sync.WaitGroup, gitLeakReceiverWG *sync.WaitGroup) {
		for gitLeak := range gitLeaks {
			b, err := json.MarshalIndent(gitLeak, "", "   ")
			if err != nil {
				fmt.Println("failed to output leak:", err)
			}
			fmt.Println(string(b))
			report = append(report, gitLeak)
			gitLeakReceiverWG.Done()
		}
	}(&commitWG, &gitLeakReceiverWG)

	if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
		log.Fatal(err)
	}

	gitFormat := "--format=%H%n%an%n%s%n%ci"
	out, err = exec.Command("git", "rev-list", "--all",
		"--remotes", "--topo-order", gitFormat).Output()
	if err != nil {
		log.Fatalf("error retrieving commits%v\n", err)
	}

	revListLines := bytes.Split(out, []byte("\n"))
	commits := parseFormattedRevList(revListLines)

	for _, commit := range commits {
		if commit.Hash == "" {
			continue
		}
		if commit.Hash == opts.SinceCommit {
			break
		}

		commitWG.Add(1)
		go func(currCommit Commit, repoName string, commitWG *sync.WaitGroup,
			gitLeakReceiverWG *sync.WaitGroup, opts *Options) {
			defer commitWG.Done()
			if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
				log.Fatal(err)
			}

			commitCmp := fmt.Sprintf("%s^!", currCommit.Hash)
			semaphoreChan <- struct{}{}
			out, err := exec.Command("git", "diff", commitCmp).Output()
			<-semaphoreChan

			if err != nil {
				if strings.Contains(err.Error(), "too many files open"){
					fmt.Printf("error retrieving diff for commit %s. Try turning concurrency down. %v\n", currCommit, err)
				}
				if opts.Tmp {
					rmTmp(owner)
				}
			}

			leaks := doChecks(string(out), currCommit, opts, repo)
			if len(leaks) == 0 {
				return
			}
			for _, leak := range leaks {
				gitLeakReceiverWG.Add(1)
				gitLeaks <- leak
			}

		}(commit, repo.name, &commitWG, &gitLeakReceiverWG, opts)
	}

	commitWG.Wait()
	gitLeakReceiverWG.Wait()
	return report
}

func parseFormattedRevList(revList [][]byte) []Commit {
	var commits []Commit
	for i := 0; i < len(revList)-1; i=i+5 {
		commit := Commit{
			Hash: string(revList[i+1]),
			Author: string(revList[i+2]),
			Msg: string(revList[i+3]),
			Time: string(revList[i+4]),
		}
		commits = append(commits, commit)
	}
	return commits
}
