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
)

// LeakElem contains the line and commit of a leak
type LeakElem struct {
	Line     string `json:"line"`
	Commit   string `json:"commit"`
	Offender string `json:"string"`
	Reason   string `json:"reason"`
}

func start(repos []RepoDesc, owner *Owner, opts *Options) {
	var report []LeakElem

	// interrupt handling
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if opts.Tmp {
			err := os.RemoveAll(owner.path)
			if err != nil {
				log.Printf("failed to properly remove tmp gitleaks dir: %v", err)
				// exit code?
			}
			os.Exit(1)
		}
	}()

	// run checks on repos
	for _, repo := range repos {
		// change to owner root
		if err := os.Chdir(fmt.Sprintf(owner.path)); err != nil {
			log.Fatal(err)
		}

		dotGitPath := filepath.Join(repo.path, ".git")
		if _, err := os.Stat(dotGitPath); err == nil {
			report = getLeaks(repo, opts)
		} else {
			fmt.Printf("Cloning \x1b[37;1m%s\x1b[0m...\n", repo.url)
			err := exec.Command("git", "clone", repo.url).Run()
			if err != nil {
				log.Printf("failed to clone repo %v", err)
				return
			}
			report = getLeaks(repo, opts)
		}

		if len(report) == 0 {
			fmt.Printf("No Leaks detected for \x1b[35;2m%s\x1b[0m...\n\n", repo.url)
		}
		fmt.Println(opts.EnableJSON)
		// write report
		if opts.EnableJSON {
			writeGitLeaksReport(report, repo, opts)
		}

	}
}

func writeGitLeaksReport(report []LeakElem, repo RepoDesc, opts *Options) {
	fmt.Println("writing report")
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
func getLeaks(repo RepoDesc, opts *Options) []LeakElem {
	var (
		out               []byte
		err               error
		commitWG          sync.WaitGroup
		gitLeakReceiverWG sync.WaitGroup
		gitLeaks          = make(chan LeakElem)
		report            []LeakElem
	)
	semaphoreChan := make(chan struct{}, opts.Concurrency)

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

	out, err = exec.Command("git", "rev-list", "--all", "--remotes", "--topo-order").Output()
	if err != nil {
		log.Fatalf("error retrieving commits%v\n", err)
	}

	commits := bytes.Split(out, []byte("\n"))
	for _, currCommitB := range commits {
		currCommit := string(currCommitB)
		if currCommit == "" {
			continue
		}
		if currCommit == opts.SinceCommit {
			break
		}

		commitWG.Add(1)
		go func(currCommit string, repoName string, commitWG *sync.WaitGroup,
			gitLeakReceiverWG *sync.WaitGroup, opts *Options) {

			defer commitWG.Done()
			if err := os.Chdir(fmt.Sprintf(repo.path)); err != nil {
				log.Fatal(err)
			}

			commitCmp := fmt.Sprintf("%s^!", currCommit)
			semaphoreChan <- struct{}{}
			out, err := exec.Command("git", "diff", commitCmp).Output()
			<-semaphoreChan

			if err != nil {
				fmt.Printf("error retrieving diff for commit %s try turning concurrency factor down %v\n", currCommit, err)
				log.Fatal(err)
			}

			leaks := doChecks(string(out), currCommit, opts)
			if len(leaks) == 0 {
				return
			}
			for _, leak := range leaks {
				gitLeakReceiverWG.Add(1)
				gitLeaks <- leak
			}

		}(currCommit, repo.name, &commitWG, &gitLeakReceiverWG, opts)
	}

	commitWG.Wait()
	gitLeakReceiverWG.Wait()
	return report
}
