package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/github"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	git "gopkg.in/src-d/go-git.v4"
	gitHttp "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

var githubPages = 100

// auditPR audits a single github PR
func auditGithubPR() ([]Leak, error) {
	var leaks []Leak
	ctx := context.Background()
	githubClient := github.NewClient(githubToken())
	splits := strings.Split(opts.GithubPR, "/")
	owner := splits[len(splits)-4]
	repo := splits[len(splits)-3]
	prNum, err := strconv.Atoi(splits[len(splits)-1])
	if err != nil {
		return nil, err
	}

	page := 1
	for {
		commits, resp, err := githubClient.PullRequests.ListCommits(ctx, owner, repo, prNum, &github.ListOptions{
			PerPage: githubPages,
			Page:    page,
		})
		if err != nil {
			return leaks, err
		}

		for _, commit := range commits {
			totalCommits = totalCommits + 1
			commit, _, err := githubClient.Repositories.GetCommit(ctx, owner, repo, *commit.SHA)
			if err != nil {
				continue
			}
			files := commit.Files
			for _, f := range files {
				skipFile := false
				if f.Patch == nil || f.Filename == nil {
					continue
				}
				for _, re := range whiteListFiles {
					if re.FindString(f.GetFilename()) != "" {
						log.Infof("skipping whitelisted file (matched regex '%s'): %s", re.String(), f.GetFilename())
						skipFile = true
						break
					}
				}
				if skipFile {
					continue
				}

				diff := gitDiff{
					sha:          commit.GetSHA(),
					content:      *f.Patch,
					filePath:     *f.Filename,
					repoName:     repo,
					githubCommit: commit,
					author:       commit.GetCommitter().GetLogin(),
					message:      *commit.Commit.Message,
					date:         *commit.Commit.Committer.Date,
				}
				leaks = append(leaks, inspect(diff)...)
			}
		}
		page = resp.NextPage
		if resp.LastPage == 0 {
			break
		}
	}

	return leaks, nil
}

// auditGithubRepos kicks off audits if --github-user or --github-org options are set.
// First, we gather all the github repositories from the github api (this doesnt actually clone the repo).
// After all the repos have been pulled from github's api we proceed to audit the repos by calling auditGithubRepo.
// If an error occurs during an audit of a repo, that error is logged but won't break the execution cycle.
func auditGithubRepos() ([]Leak, error) {
	var (
		err              error
		githubRepos      []*github.Repository
		pagedGithubRepos []*github.Repository
		resp             *github.Response
		githubOrgOptions *github.RepositoryListByOrgOptions
		githubOptions    *github.RepositoryListOptions
		done             bool
		leaks            []Leak
		ownerDir         string
	)
	ctx := context.Background()
	githubClient := github.NewClient(githubToken())

	if opts.GithubOrg != "" {
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}
		githubOrgOptions = &github.RepositoryListByOrgOptions{
			ListOptions: github.ListOptions{PerPage: 100},
		}
	} else if opts.GithubUser != "" {
		if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
			ghURL, _ := url.Parse(opts.GithubURL)
			githubClient.BaseURL = ghURL
		}

		githubOptions = &github.RepositoryListOptions{
			Affiliation: "owner",
			ListOptions: github.ListOptions{
				PerPage: 100,
			},
		}
	}

	for {
		if done {
			break
		}
		if opts.GithubUser != "" {
			pagedGithubRepos, resp, err = githubClient.Repositories.List(ctx, opts.GithubUser, githubOptions)
			if err != nil {
				done = true
			}
			githubOptions.Page = resp.NextPage
			githubRepos = append(githubRepos, pagedGithubRepos...)
			if resp.NextPage == 0 {
				done = true
			}
		} else if opts.GithubOrg != "" {
			pagedGithubRepos, resp, err = githubClient.Repositories.ListByOrg(ctx, opts.GithubOrg, githubOrgOptions)
			if err != nil {
				done = true
			}
			githubOrgOptions.Page = resp.NextPage
			githubRepos = append(githubRepos, pagedGithubRepos...)
			if resp.NextPage == 0 {
				done = true
			}
		}
		if opts.Log == "Debug" || opts.Log == "debug" {
			for _, githubRepo := range pagedGithubRepos {
				log.Debugf("staging repos %s", *githubRepo.Name)
			}
		}
	}
	if opts.Disk {
		ownerDir, _ = ioutil.TempDir(dir, opts.GithubUser)
	}
	for _, githubRepo := range githubRepos {
		repo, err := cloneGithubRepo(githubRepo)
		if err != nil {
			log.Warn(err)
			continue
		}
		leaksFromRepo, err := auditGitRepo(repo)
		if err != nil {
			log.Warn(err)
			continue
		}
		if opts.Disk {
			os.RemoveAll(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name))
		}
		if len(leaksFromRepo) == 0 {
			log.Infof("no leaks found for repo %s", *githubRepo.Name)
		} else {
			log.Warnf("leaks found for repo %s", *githubRepo.Name)
		}
		if err != nil {
			log.Warn(err)
		}
		leaks = append(leaks, leaksFromRepo...)
	}
	return leaks, nil
}

// cloneGithubRepo clones a repo from the url parsed from a github repo. The repo
// will be cloned to disk if --disk is set. If the repo is private, you must include the
// --private/-p option. After the repo is clone, an audit will begin.
func cloneGithubRepo(githubRepo *github.Repository) (*RepoDescriptor, error) {
	var (
		repo *git.Repository
		err  error
	)
	githubToken := os.Getenv("GITHUB_TOKEN")
	if opts.ExcludeForks && githubRepo.GetFork() {
		return nil, fmt.Errorf("skipping %s, excluding forks", *githubRepo.Name)
	}
	for _, re := range whiteListRepos {
		if re.FindString(*githubRepo.Name) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", *githubRepo.Name)
		}
	}
	log.Infof("cloning: %s", *githubRepo.Name)
	if opts.Disk {
		ownerDir, err := ioutil.TempDir(dir, opts.GithubUser)
		if err != nil {
			return nil, fmt.Errorf("unable to generater owner temp dir: %v", err)
		}
		if sshAuth != nil && githubToken == "" {
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name), false, &git.CloneOptions{
				URL:  *githubRepo.SSHURL,
				Auth: sshAuth,
			})
		} else if githubToken != "" {
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name), false, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
				Auth: &gitHttp.BasicAuth{
					Username: "fakeUsername", // yes, this can be anything except an empty string
					Password: githubToken,
				},
			})
		} else {
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, *githubRepo.Name), false, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
			})
		}
	} else {
		if sshAuth != nil && githubToken == "" {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:  *githubRepo.SSHURL,
				Auth: sshAuth,
			})
		} else if githubToken != "" {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
				Auth: &gitHttp.BasicAuth{
					Username: "fakeUsername", // yes, this can be anything except an empty string
					Password: githubToken,
				},
			})
		} else {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL: *githubRepo.CloneURL,
			})
		}
	}
	if err != nil {
		return nil, err
	}
	return &RepoDescriptor{
		repository: repo,
		name:       *githubRepo.Name,
	}, nil
}

// githubToken returns an oauth2 client for the github api to consume. This token is necessary
// if you are running audits with --github-user or --github-org
func githubToken() *http.Client {
	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		return nil
	}
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: githubToken},
	)
	return oauth2.NewClient(context.Background(), ts)
}
