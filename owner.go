package main

import (
	"context"
	"fmt"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
)

// Owner represents the owner of a repo or group of repos.
// Owners can fall under three categories depending on how
// Gitleaks is ran; ambiguous, user, or organization.
// An ambiguous implies that gitleaks is running on a single
// repo from github or locally.
type Owner struct {
	name        string
	url         string
	accountType string
	path        string
	reportPath  string
	repos       []Repo
}

// ownerPath is used by newOwner and is responsible for returning a path parsed from
// opts.ClonePath, PWD, or a temporary directory. If a user provides --clone-path=$Home/Desktop/audits
// then the owner path with be $HOME/Desktop/audits. If the user does not provide a --clone-path= argument
// then ownerPath will return the current working directory. If the user sets the temporary option, then
// ownerPath will be $TMPDIR/ownerName. For example running gitleaks on github.com/mozilla, ownerPath would
// return $TMPDIR/mozilla
func ownerPath(ownerName string) (string, error) {
	if opts.Tmp {
		dir, err := ioutil.TempDir("", ownerName)
		return dir, err
	} else if opts.ClonePath != "" {
		if _, err := os.Stat(opts.ClonePath); os.IsNotExist(err) {
			os.Mkdir(opts.ClonePath, os.ModePerm)
		}
		return opts.ClonePath, nil
	} else {
		return os.Getwd()
	}
}

// newOwner is the entry point for gitleaks after all the options have been parsed and
// is responsible for returning an Owner pointer. If running in localmode then the Owner
// that gets created will create a single repo specified in opts.RepoPath. Otherwise
// newOwner will go out to github and fetch all the repos associated with the owner if
// gitleaks is running in owner mode. If gitleaks is running in a non-local repo mode, then
// newOwner will skip hitting the github api and go directly to cloning.
func newOwner() *Owner {
	name := ownerName()
	ownerPath, err := ownerPath(name)
	if err != nil {
		log.Fatal(err)
	}
	owner := &Owner{
		name:        name,
		url:         opts.URL,
		accountType: ownerType(),
		path:        ownerPath,
	}

	// listen for ctrl-c
	// NOTE: need some help on how to actually shut down gracefully.
	// On interrupt a repo may still be trying to clone... This has no
	// actual effect other than extraneous logging.
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, os.Interrupt, os.Interrupt)
	go func() {
		<-sigC
		if opts.Tmp {
			owner.rmTmp()
		}
		os.Exit(ExitFailure)
	}()

	err = owner.fetchRepos()
	if err != nil {
		log.Fatal(err)
	}
	return owner
}

// fetchRepos is used by newOwner and is responsible for fetching one or more
// of the owner's repos. If opts.RepoURL is not the empty string then fetchRepos will
// only grab the repo specified in opts.RepoURL. Otherwise, fetchRepos will reach out to
// github's api and grab all repos associated with owner.
func (owner *Owner) fetchRepos() error {
	var err error
	ctx := context.Background()

	// local mode, single repo, ambiguous account type
	if opts.LocalMode {
		_, repoName := path.Split(opts.RepoPath)
		repo := newRepo(repoName, "", opts.RepoPath)
		owner.repos = append(owner.repos, *repo)
		return nil
	}

	if owner.accountType == "" {
		// single repo, ambiguous account type
		_, repoName := path.Split(opts.URL)
		repo := newRepo(repoName, opts.URL, owner.path+"/"+repoName)
		owner.repos = append(owner.repos, *repo)
	} else {
		// org or user account type, would fail if not valid before
		tokenClient := githubTokenClient()
		gitClient := github.NewClient(tokenClient)

		if owner.accountType == "org" {
			// org account type
			orgOpt := &github.RepositoryListByOrgOptions{
				ListOptions: github.ListOptions{PerPage: 10},
			}
			err = owner.fetchOrgRepos(ctx, orgOpt, gitClient)
		} else {
			// user account type
			userOpt := &github.RepositoryListOptions{
				ListOptions: github.ListOptions{PerPage: 10},
			}
			err = owner.fetchUserRepos(ctx, userOpt, gitClient)
		}
	}
	return err
}

// fetchOrgRepos used by fetchRepos is responsible for parsing github's org repo response. If no
// github token is available then fetchOrgRepos might run into a rate limit in which case owner will
// log an error and gitleaks will exit. The rate limit for no token is 50 req/hour... not much.
func (owner *Owner) fetchOrgRepos(ctx context.Context, orgOpts *github.RepositoryListByOrgOptions,
	gitClient *github.Client) error {
	var (
		githubRepos []*github.Repository
		resp        *github.Response
		err         error
	)

	for {
		githubRepos, resp, err = gitClient.Repositories.ListByOrg(
			ctx, owner.name, orgOpts)
		owner.addRepos(githubRepos)
		if _, ok := err.(*github.RateLimitError); ok {
			log.Printf("hit rate limit retreiving %s, continuing with partial audit\n",
				owner.name)
		} else if err != nil {
			return fmt.Errorf("failed obtaining %s repos from githuib api, bad request", owner.name)
		} else if resp.NextPage == 0 {
			break
		}
		orgOpts.Page = resp.NextPage
	}
	return nil
}

// fetchUserRepos used by fetchRepos is responsible for parsing github's user repo response. If no
// github token is available then fetchUserRepos might run into a rate limit in which case owner will
// log an error and gitleaks will exit. The rate limit for no token is 50 req/hour... not much.
// sorry for the redundancy
func (owner *Owner) fetchUserRepos(ctx context.Context, userOpts *github.RepositoryListOptions,
	gitClient *github.Client) error {
	var (
		githubRepos []*github.Repository
		resp        *github.Response
		err         error
	)
	for {
		githubRepos, resp, err = gitClient.Repositories.List(
			ctx, owner.name, userOpts)
		owner.addRepos(githubRepos)
		if _, ok := err.(*github.RateLimitError); ok {
			log.Printf("hit rate limit retreiving %s, continuing with partial audit\n",
				owner.name)
			break
		} else if err != nil {
			return fmt.Errorf("failed obtaining %s repos from github api, bad request", owner.name)
		} else if resp.NextPage == 0 {
			break
		}
		userOpts.Page = resp.NextPage
	}
	return nil
}

// addRepos used by fetchUserRepos and fetchOrgRepos appends new repos from
// github's org/user response.
func (owner *Owner) addRepos(githubRepos []*github.Repository) {
	for _, repo := range githubRepos {
		owner.repos = append(owner.repos, *newRepo(*repo.Name, *repo.CloneURL, owner.path+"/"+*repo.Name))
	}
}

// auditRepos is responsible for auditing all the owner's
// repos. auditRepos is used by main and will return the following exit codes
// 0: The audit succeeded with no findings
// 1: The audit failed, or wasn't attempted due to an execution failure.
// 2: The audit succeeded, and secrets / patterns were found.
func (owner *Owner) auditRepos() int {
	exitCode := ExitClean
	for _, repo := range owner.repos {
		leaksPst, err := repo.audit()
		if err != nil {
			log.Fatal(err)
		}
		if leaksPst {
			exitCode = ExitLeaks
		}
	}
	if opts.Tmp {
		owner.rmTmp()
	}
	return exitCode
}

// rmTmp removes the owner's temporary repo. rmTmp will only get called if temporary
// mode is set. rmTmp is called on a SIGINT and after the audits have finished
func (owner *Owner) rmTmp() {
	log.Printf("removing tmp gitleaks repo for %s\n", owner.path)
	os.RemoveAll(owner.path)
}

// ownerType returns the owner type extracted from opts.
// If no owner type is provided, gitleaks assumes the owner is ambiguous
// and the user is running gitleaks on a single repo
func ownerType() string {
	if opts.OrgMode {
		return "org"
	} else if opts.UserMode {
		return "user"
	}
	return ""
}

// ownerName returns the owner name extracted from the urls provided in opts.
// If no RepoURL, OrgURL, or UserURL is provided, then owner will log an error
// and gitleaks will exit.
func ownerName() string {
	if opts.RepoMode {
		splitSlashes := strings.Split(opts.URL, "/")
		return splitSlashes[len(splitSlashes)-2]
	} else if opts.UserMode || opts.OrgMode {
		_, ownerName := path.Split(opts.URL)
		return ownerName
	}
	// local repo
	return ""
}

// githubTokenClient creates an oauth client from your github access token.
// Gitleaks will attempt to retrieve your github access token from a cli argument
// or an env var - "GITHUB_TOKEN".
func githubTokenClient() *http.Client {
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
