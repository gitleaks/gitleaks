package hosts

import (
	"context"
	"fmt"
	"github.com/google/go-github/github"
	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks/audit"
	"github.com/zricethezav/gitleaks/manager"
	"github.com/zricethezav/gitleaks/options"
	"golang.org/x/oauth2"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"strconv"
	"strings"
	"sync"
)

type GithubError struct {
	Err    string
	Repo   string
	Commit string
}

func (githubError *GithubError) Error() string {
	return fmt.Sprintf("repo: %s, err: %s",
		githubError.Repo, githubError.Err)
}

type Github struct {
	client  *github.Client
	errChan chan GithubError
	manager manager.Manager
	wg      sync.WaitGroup
}

func NewGithubClient(m manager.Manager) *Github {
	ctx := context.Background()
	token := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: options.GetAccessToken(m.Opts)},
	)

	return &Github{
		manager: m,
		client:  github.NewClient(oauth2.NewClient(ctx, token)),
		errChan: make(chan GithubError),
	}
}

// Audit will audit a github user or organization's repos.
func (g *Github) Audit() {
	ctx := context.Background()
	listOptions := github.ListOptions{
		PerPage: 100,
	}

	var githubRepos []*github.Repository

	for {
		var (
			_githubRepos []*github.Repository
			resp         *github.Response
			err          error
		)
		if g.manager.Opts.User != "" {
			_githubRepos, resp, err = g.client.Repositories.List(ctx, g.manager.Opts.User,
				&github.RepositoryListOptions{ListOptions: listOptions})
		} else if g.manager.Opts.Organization != "" {
			_githubRepos, resp, err = g.client.Repositories.ListByOrg(ctx, g.manager.Opts.Organization,
				&github.RepositoryListByOrgOptions{ListOptions: listOptions})
		}

		githubRepos = append(githubRepos, _githubRepos...)

		if resp == nil {
			break
		}
		listOptions.Page = resp.NextPage
		if err != nil || listOptions.Page == 0 {
			break
		}
	}

	for _, repo := range githubRepos {
		r := audit.NewRepo(&g.manager)
		err := r.Clone(&git.CloneOptions{
			URL: *repo.CloneURL,
		})
		r.Name = *repo.Name
		if err != nil {
			log.Warn(err)
		}

		if err = r.Audit(); err != nil {
			log.Warn(err)
		}
	}
}

// AuditPR audits a single github PR
func (g *Github) AuditPR() {
	ctx := context.Background()
	splits := strings.Split(g.manager.Opts.PullRequest, "/")
	owner := splits[len(splits)-4]
	repoName := splits[len(splits)-3]
	prNum, err := strconv.Atoi(splits[len(splits)-1])
	repo := audit.NewRepo(&g.manager)
	repo.Name = repoName
	log.Infof("auditing pr %s\n", g.manager.Opts.PullRequest)

	if err != nil {
		return
	}
	page := 1
	for {
		commits, resp, err := g.client.PullRequests.ListCommits(ctx, owner, repoName, prNum, &github.ListOptions{
			PerPage: 100, Page: page})
		if err != nil {
			return
		}
		for _, c := range commits {
			c, _, err := g.client.Repositories.GetCommit(ctx, owner, repo.Name, *c.SHA)
			if err != nil {
				continue
			}
			commitObj := object.Commit{
				Hash: plumbing.NewHash(*c.SHA),
				Author: object.Signature{
					Name:  *c.Commit.Author.Name,
					Email: *c.Commit.Author.Email,
					When:  *c.Commit.Author.Date,
				},
			}
			for _, f := range c.Files {
				if f.Patch == nil {
					continue
				}
				audit.InspectString(*f.Patch, &commitObj, repo, *f.Filename)
			}
		}
		page = resp.NextPage
		if resp.LastPage == 0 {
			break
		}
	}
}
