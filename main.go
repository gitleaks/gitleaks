package main

import (
	"bytes"
	_ "fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// go get hunt is a github secret key hunter written in go. target organizations, users, and remote/local repos
// gotta be fast

type Repo struct {
	url      string
	name     string
	path     string
	branches *Branch
}

type Branch struct {
	name string
}

var appRoot string

func init() {
	appRoot, _ = os.Getwd()
}

func main() {
	args := os.Args[1:]
	opts := parseOptions(args)
	start(opts)
}

func start(opts *Options) {
	if opts.Repo != "" {
		repoStart(opts.Repo)
	}
}

func repoStart(repo_url string) {
	err := exec.Command("git", "clone", repo_url).Run()
	if err != nil {
		log.Fatalf("failed to clone repo %v", err)
	}
	repo_name := strings.Split(repo_url, "/")[4]
	if err := os.Chdir(repo_name); err != nil {
		log.Fatal(err)
	}

	repo := Repo{repo_url, repo_name, "", nil}
	repo.audit()
	repo.cleanup()
}

// cleanup changes to app root and recursive rms target repo
func (repo Repo) cleanup() {
	if err := os.Chdir(appRoot); err != nil {
		log.Fatalf("failed cleaning up repo %v", err)
	}
	err := exec.Command("rm", "-rf", repo.name).Run()
	if err != nil {
		log.Fatal(err)
	}
}

// (Repo) audit parses git branch --all to audit remote branches
func (repo Repo) audit() {
	var out []byte
	var err error
	var branch string
	var commits [][]byte

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
		out, err = exec.Command("git", "rev-list", branch).Output()
		if err != nil {
			log.Fatalf("error retrieving commits %v\n", err)
		}
		// iterate through commits
		commits = bytes.Split(out, []byte("\n"))
		for j, commitB := range commits {
			if j == len(commits)-2 {
				break
			}
			diff(string(commitB), string(commits[j+1]))
		}
	}
}

func diff(commit1 string, commit2 string) {
	// fmt.Println(commit1, commit2)
	_, err := exec.Command("git", "diff", commit1, commit2).Output()
	if err != nil {
		log.Fatalf("error retrieving commits %v\n", err)
	}
	//fmt.Printf("%s\n", out)
}
