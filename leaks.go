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
	Lines  []string `json:"lines"`
	Commit string   `json:"commit"`
}

type GitLeak struct {
	leaks  []string
	commit string
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
		wg            sync.WaitGroup
		concurrent    = 100
		semaphoreChan = make(chan struct{}, concurrent)
		gitLeaks      = make(chan GitLeak)
	)

	out, err = exec.Command("git", "rev-list", "--all", "--remotes", "--topo-order").Output()
	if err != nil {
		log.Fatalf("error retrieving commits%v\n", err)
	}

	commits := bytes.Split(out, []byte("\n"))
	for j, currCommitB := range commits {
		currCommit := string(currCommitB)
		if j == len(commits)-2 {
			break
		}

		wg.Add(1)
		go func(currCommit string, repoName string) {
			defer wg.Done()
			var leakPrs bool
			var leaks []string

			if err := os.Chdir(fmt.Sprintf("%s/%s", appRoot, repoName)); err != nil {
				log.Fatal(err)
			}

			commitCmp := fmt.Sprintf("%s^!", currCommit)
			semaphoreChan <- struct{}{}
			out, err := exec.Command("git", "diff", commitCmp).Output()
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

			gitLeaks <- GitLeak{leaks, currCommit}

		}(currCommit, repoName)
	}
	go func() {
		for gitLeak := range gitLeaks {
			if len(gitLeak.leaks) != 0 {
				fmt.Println(gitLeak.leaks)
				report = append(report, ReportElem{gitLeak.leaks, gitLeak.commit})
			}
		}
	}()
	wg.Wait()

	return report
}
