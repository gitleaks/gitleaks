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
	"strings"
	"sync"
	"syscall"
)

type ReportElem struct {
	Lines   []string `json:"lines"`
	Branch  string   `json:"branch"`
	CommitA string   `json:"commitA"`
	CommitB string   `json:"commitB"`
}

type GitLeak struct {
	hash    string
	leaks   []string
	commitA string
	commitB string
	branch  string
}

func start(opts *Options, repoUrl string) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	err := exec.Command("git", "clone", repoUrl).Run()
	if err != nil {
		log.Fatalf("failed to clone repo %v", err)
	}
	repoName := strings.Split(repoUrl, "/")[4]
	if err := os.Chdir(repoName); err != nil {
		log.Fatal(err)
	}
	go func() {
		<-c
		cleanup(repoName)
		os.Exit(1)
	}()

	report := getLeaks(repoName)
	cleanup(repoName)

	reportJson, _ := json.MarshalIndent(report, "", "\t")
	err = ioutil.WriteFile(fmt.Sprintf("%s_leaks.json", repoName), reportJson, 0644)
}

// cleanup changes to app root and recursive rms target repo
func cleanup(repoName string) {
	if err := os.Chdir(appRoot); err != nil {
		log.Fatalf("failed cleaning up repo. Does the repo exist? %v", err)
	}
	err := exec.Command("rm", "-rf", repoName).Run()
	if err != nil {
		log.Fatal(err)
	}
}

// audit parses git branch --all
func getLeaks(repoName string) []ReportElem {
	var (
		out           []byte
		err           error
		branch        string
		commits       [][]byte
		wg            sync.WaitGroup
		commitA       string
		commitB       string
		concurrent    = 100
		semaphoreChan = make(chan struct{}, concurrent)
		gitLeaks      = make(chan GitLeak)
		cmdLock       = sync.Mutex{}
		cache         = make(map[string]bool)
	)

	out, err = exec.Command("git", "branch", "--all").Output()
	if err != nil {
		log.Fatalf("error retrieving branches %v\n", err)
	}

	// iterate through branches, git rev-list <branch>
	branches := bytes.Split(out, []byte("\n"))

	for i, branchB := range branches {
		if i < 2 || i == len(branches)-1 {
			continue
		}
		branch = string(bytes.Trim(branchB, " "))
		cmdLock.Lock()
		out, err := exec.Command("git", "rev-list", "--topo-order", branch).Output()
		cmdLock.Unlock()
		if err != nil {
			fmt.Println("skipping branch", branch, err)
			continue
		}

		// iterate through commits
		commits = bytes.Split(out, []byte("\n"))
		for j, currCommit := range commits {
			if j == len(commits)-2 {
				break
			}
			commitA = string(commits[j+1])
			commitB = string(currCommit)
			_, seen := cache[commitA+commitB]
			if seen {
				continue
			} else {
				cache[commitA+commitB] = true
			}

			wg.Add(1)
			go func(commitA string, commitB string, branch string, repoName string) {
				defer wg.Done()
				var leakPrs bool
				var leaks []string

				if err := os.Chdir(fmt.Sprintf("%s/%s", appRoot, repoName)); err != nil {
					log.Fatal(err)
				}

				semaphoreChan <- struct{}{}
				out, err := exec.Command("git", "diff", commitA, commitB).Output()
				<-semaphoreChan

				if err != nil {
					return
				}
				lines := checkRegex(string(out))
				if len(lines) == 0 {
					return
				}

				for _, line := range lines {
					leakPrs = checkEntropy(line)
					if leakPrs {
						leaks = append(leaks, line)
					}
				}

				gitLeaks <- GitLeak{commitA + commitB, leaks, commitA, commitB, branch}

			}(commitA, commitB, branch, repoName)
		}
	}
	go func() {
		for gitLeak := range gitLeaks {
			if len(gitLeak.leaks) != 0 {
				fmt.Println(gitLeak.branch)
				report = append(report, ReportElem{gitLeak.leaks, gitLeak.branch,
					gitLeak.commitA, gitLeak.commitB})
			}
		}
	}()
	wg.Wait()

	return report
}
