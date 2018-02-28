package main

import (
	"path"
	"io/ioutil"
	"path/filepath"
	"os"
	"github.com/google/go-github/github"
	"strings"
	"context"
	"golang.org/x/oauth2"
	"net/http"
	"log"
	"os/signal"
	_"fmt"
)

type Owner struct {
	name        string
	url         string
	accountType string
	path        string
	reportPath  string
	repos      []Repo
}

// newOwner instantiates an owner and creates any necessary resources for said owner.
// newOwner returns a Owner struct pointer
func newOwner(opts *Options) *Owner {
	name, err := ownerName(opts)
	owner := &Owner{
		name:        name,
		url:         opts.UserURL,
		accountType: ownerType(opts),
	}

	if err != nil {
		owner.failf()
	}

	// listen for ctrl-c
	// NOTE: need some help on how to actually shut down gracefully.
	// On interrupt a repo may still be trying to clone... This has no
	// actual effect other than extraneous logging.
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt, os.Interrupt)
	go func() {
		<-sigC
		owner.rmTmp()
	}()

	owner.setupDir(opts)
	owner.fetchRepos(opts)
	return owner
}

// fetchRepos is used by newOwner and is responsible for fetching one or more
// of the owner's repos. If opts.RepoURL is not the empty string then fetchRepos will
// only grab the repo specified in opts.RepoURL. Otherwise, fetchRepos will reach out to
// github's api and grab all repos associated with owner.
func (owner *Owner) fetchRepos(opts *Options) {
	ctx := context.Background()
	if owner.accountType == "" {
		// single repo, ambiguous account type
		_, repoName := path.Split(opts.RepoURL)
		repo := newRepo(owner, repoName, opts.RepoURL)
		owner.repos = append(owner.repos, *repo)
	} else {
		// org or user account type, would fail if not valid before
		tokenClient := githubTokenClient(opts)
		gitClient := github.NewClient(tokenClient)

		if owner.accountType == "org" {
			// org account type
			orgOpt := &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{PerPage: 10},
			}
			owner.fetchOrgRepos(orgOpt, gitClient, ctx)
		} else {
			// user account type
			userOpt := &github.RepositoryListOptions{
				ListOptions: github.ListOptions{PerPage: 10},
			}
			owner.fetchUserRepos(userOpt, gitClient, ctx)
		}
	}
}

// fetchOrgRepos used by fetchRepos is responsible for parsing github's org repo response. If no
// github token is available then fetchOrgRepos might run into a rate limit in which case owner will
// log an error and gitleaks will exit. The rate limit for no token is 50 req/hour... not much.
func (owner *Owner) fetchOrgRepos(orgOpts *github.RepositoryListByOrgOptions, gitClient *github.Client,
	ctx context.Context) {
	var (
		githubRepos     []*github.Repository
		resp 			 *github.Response
		err 			error
	)

	for {
		githubRepos, resp, err = gitClient.Repositories.ListByOrg(
			ctx, owner.name, orgOpts)
		owner.addRepos(githubRepos)
		if _, ok := err.(*github.RateLimitError); ok {
			log.Println("hit rate limit")
			break
		} else if err != nil {
			log.Println("other error")
			break
		} else if resp.NextPage == 0 {
			break
		}
		orgOpts.Page = resp.NextPage
	}
}

// fetchUserRepos used by fetchRepos is responsible for parsing github's user repo response. If no
// github token is available then fetchUserRepos might run into a rate limit in which case owner will
// log an error and gitleaks will exit. The rate limit for no token is 50 req/hour... not much.
// sorry for the redundancy
func (owner *Owner) fetchUserRepos(userOpts *github.RepositoryListOptions, gitClient *github.Client,
	ctx context.Context) {
	var (
		githubRepos     []*github.Repository
		resp 			 *github.Response
		err 			error
	)
	for {
		githubRepos, resp, err = gitClient.Repositories.List(
			ctx, owner.name, userOpts)
		owner.addRepos(githubRepos)
		if _, ok := err.(*github.RateLimitError); ok {
			log.Println("hit rate limit")
			break
		} else if err != nil {
			log.Println("other error")
			break
		} else if resp.NextPage == 0 {
			break
		}
		userOpts.Page = resp.NextPage
	}
}

// addRepos used by fetchUserRepos and fetchOrgRepos appends new repos from
// github's org/user response.
func (owner *Owner) addRepos (githubRepos []*github.Repository) {
	for _, repo := range githubRepos {
		owner.repos = append(owner.repos, *newRepo(owner, *repo.Name, *repo.CloneURL))
	}
}

// auditRepos
func (owner *Owner) auditRepos(opts *Options) {
	for _, repo := range owner.repos {
		err := repo.audit(owner, opts)
		if err != nil {
			owner.failf()
		}
	}
}

// failf
func (owner *Owner) failf() {
	// TODO
}

// exitNow
func (owner *Owner) exitNow() {

}

// setupDir sets up the owner's directory for clones and reports.
// If the temporary option is set then a temporary directory will be
// used for the owner repo clones.
func (owner *Owner) setupDir(opts *Options) {
	if opts.Tmp {
		dir, err := ioutil.TempDir("", owner.name)
		if err != nil {
			owner.failf()
		}
		owner.path = dir
	} else {
		owner.path = filepath.Join(gitLeaksClonePath, owner.name)
		if _, err := os.Stat(owner.path); os.IsNotExist(err) {
			os.Mkdir(owner.path, os.ModePerm)
		}
	}
	owner.reportPath = filepath.Join(gitLeaksPath, "report", owner.name)
}

// rmTmp removes the temporary repo
func (owner *Owner) rmTmp() {
	os.RemoveAll(owner.path)
	os.Exit(EXIT_FAILURE)
}

// ownerType returns the owner type extracted from opts.
// If no owner type is provided, gitleaks assumes the owner is ambiguous
// and the user is running gitleaks on a single repo
func ownerType(opts *Options) string {
	if opts.OrgURL != "" {
		return "org"

	} else if opts.UserURL != "" {
		return "user"
	}
	return ""
}

// ownerName returns the owner name extracted from the urls provided in opts.
// If no RepoURL, OrgURL, or UserURL is provided, then owner will log an error
// and gitleaks will exit.
func ownerName(opts *Options) (string, error) {
	if opts.RepoURL != "" {
		splitSlashes := strings.Split(opts.RepoURL, "/")
		return splitSlashes[len(splitSlashes)-2], nil
	} else if opts.UserURL != "" {
		_, ownerName := path.Split(opts.UserURL)
		return ownerName, nil
	} else if opts.OrgURL != "" {
		_, ownerName := path.Split(opts.OrgURL)
		return ownerName, nil
	}

	// TODO error
	return "", nil
}

// githubTokenClient creates an oauth client from your github access token.
// Gitleaks will attempt to retrieve your github access token from a cli argument
// or an env var - "GITHUB_TOKEN".
// Might be good to eventually parse the token from a config or creds file in
// $GITLEAKS_HOME
func githubTokenClient(opts *Options) *http.Client {
	var token string
	if opts.Token != "" {
		token = opts.Token
	} else {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return nil
	}

	tokenService := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tokenClient := oauth2.NewClient(context.Background(), tokenService)
	return tokenClient
}
