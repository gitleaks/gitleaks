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
		leaks   []string
		wg      sync.WaitGroup
	)

	out, err = exec.Command("git", "branch", "--all").Output()
	if err != nil {
		log.Fatalf("error retrieving branches %v\n", err)
	}

	// iterate through branches, git rev-list <branch>
	branches := bytes.Split(out, []byte("\n"))

	messages := make(chan string)
	wg.Add(len(branches) - 3)

	for i, branchB := range branches {
		if i < 2 || i == len(branches)-1 {
			continue
		}
		branch = string(bytes.Trim(branchB, " "))
		go func(branch string) {
			defer wg.Done()
			cmd := exec.Command("git", "rev-list", branch)

			if err := os.Chdir(fmt.Sprintf("%s/%s", appRoot, repo.name)); err != nil {
				log.Fatal(err)
			}

			out, err := cmd.Output()
			if err != nil {
				log.Fatal(err)
			}
			// iterate through commits
			commits = bytes.Split(out, []byte("\n"))
			for j, commitB := range commits {
				fmt.Println(branch, string(commitB), j)
				if j == len(commits)-2 {
					break
				}

				leaks = checkDiff(string(commitB), string(commits[j+1]))
				if len(leaks) != 0 {
					report = append(report, ReportElem{leaks, branch,
						string(commitB), string(commits[j+1])})
				}
			}
			messages <- branch
		}(branch)
		go func() {
			for i := range messages {
				fmt.Println(i)
			}
		}()

	}
	wg.Wait()

	return report
}
