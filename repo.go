package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

type ReportElem struct {
	Lines   []string `json:"lines"`
	Branch  string   `json:"branch"`
	CommitA string   `json:"commitA"`
	CommitB string   `json:"commitB"`
}

type Repo struct {
	url  string
	name string
	path string
}

type MemoMessage struct {
	hash    string
	leaks   []string
	commitA string
	commitB string
	branch  string
}

var lock = sync.RWMutex{}
var cmdLock = sync.Mutex{}

func repoStart(repoUrl string) {
	err := exec.Command("git", "clone", repoUrl).Run()
	if err != nil {
		log.Fatalf("failed to clone repo %v", err)
	}
	repoName := strings.Split(repoUrl, "/")[4]
	if err := os.Chdir(repoName); err != nil {
		log.Fatal(err)
	}

	repo := Repo{repoUrl, repoName, ""}
	report := repo.audit()
	repo.cleanup()

	reportJson, _ := json.MarshalIndent(report, "", "\t")
	err = ioutil.WriteFile(fmt.Sprintf("%s_leaks.json", repo.name), reportJson, 0644)
}

// cleanup changes to app root and recursive rms target repo
func (repo Repo) cleanup() {
	if err := os.Chdir(appRoot); err != nil {
		log.Fatalf("failed cleaning up repo. Does the repo exist? %v", err)
	}
	err := exec.Command("rm", "-rf", repo.name).Run()
	if err != nil {
		log.Fatal(err)
	}
}

// audit parses git branch --all
func (repo Repo) audit() []ReportElem {
	var (
		out     []byte
		err     error
		branch  string
		commits [][]byte
		// leaks   []string
		wg            sync.WaitGroup
		commitA       string
		commitB       string
		concurrent    = 10
		semaphoreChan = make(chan struct{}, concurrent)
	)

	out, err = exec.Command("git", "branch", "--all").Output()
	if err != nil {
		log.Fatalf("error retrieving branches %v\n", err)
	}

	// iterate through branches, git rev-list <branch>
	branches := bytes.Split(out, []byte("\n"))

	messages := make(chan MemoMessage)

	for i, branchB := range branches {
		if i < 2 || i == len(branches)-1 {
			continue
		}
		branch = string(bytes.Trim(branchB, " "))
		cmdLock.Lock()
		cmd := exec.Command("git", "rev-list", branch)
		out, err := cmd.Output()
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
				fmt.Println("WE HAVE SEEN THIS")
				continue
			} else {
				cache[commitA+commitB] = true
			}

			wg.Add(1)
			go func(commitA string, commitB string,
				j int, branch string) {
				defer wg.Done()
				var leakPrs bool
				var leaks []string
				fmt.Println(j, branch)

				if err := os.Chdir(fmt.Sprintf("%s/%s", appRoot, repo.name)); err != nil {
					log.Fatal(err)
				}

				semaphoreChan <- struct{}{}
				fmt.Println("diffing", branch, j)
				cmd := exec.Command("git", "diff", commitA, commitB)
				out, err := cmd.Output()
				<-semaphoreChan

				if err != nil {
					fmt.Println("no diff: ", err)
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

				messages <- MemoMessage{commitA + commitB, leaks, commitA, commitB, branch}

			}(commitA, commitB, j, branch)
		}
	}
	go func() {
		for memoMsg := range messages {
			fmt.Println(memoMsg)
			if len(memoMsg.leaks) != 0 {
				report = append(report, ReportElem{memoMsg.leaks, memoMsg.branch,
					memoMsg.commitA, memoMsg.commitB})
			}
		}
	}()
	wg.Wait()

	return report
}
