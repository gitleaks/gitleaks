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

type LeakElem struct {
	Line   string `json:"line"`
	Commit string `json:"commit"`
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

func cleanup(repoName string) {
	if err := os.Chdir(appRoot); err != nil {
		log.Fatalf("failed cleaning up repo. Does the repo exist? %v", err)
	}
	err := exec.Command("rm", "-rf", repoName).Run()
	if err != nil {
		log.Fatal(err)
	}
}

func getLeaks(repoName string) []LeakElem {
	var (
		out           []byte
		err           error
		wg            sync.WaitGroup
		concurrent    = 100
		semaphoreChan = make(chan struct{}, concurrent)
		gitLeaks      = make(chan LeakElem)
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
					gitLeaks <- LeakElem{line, currCommit}
				}
			}

		}(currCommit, repoName)
	}
	go func() {
		for gitLeak := range gitLeaks {
			fmt.Println(gitLeak)
			report = append(report, gitLeak)
		}
	}()
	wg.Wait()

	return report
}
