package main

import (
	"context"
	_ "fmt"
	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"fmt"
)

type Owner struct {
	name        string
	url         string
	accountType string
	path        string
	reportPath  string
	repos       []Repo
}

// newOwner instantiates an owner and creates any necessary resources for said owner.
// newOwner returns a Owner struct pointer
func newOwner() (*Owner)  {
	name  := ownerName()
	owner := &Owner{
		name:        name,
		url:         opts.URL,
		accountType: ownerType(),
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


	// if running on local repo, just go right to it.
	if opts.LocalMode {
		repo := newLocalRepo(opts.RepoPath)
		owner.repos = append(owner.repos, *repo)
		return owner
	}

	err := owner.setupDir()
	if err != nil {
		owner.failF("%v", err)
	}

	err = owner.fetchRepos()
	if err != nil {
		owner.failF("%v", err)
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
	if owner.accountType == "" {
		// single repo, ambiguous account type
		_, repoName := path.Split(opts.URL)
		repo := newRepo(repoName, opts.URL)
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
			err = owner.fetchOrgRepos(orgOpt, gitClient, ctx)
		} else {
			// user account type
			userOpt := &github.RepositoryListOptions{
				ListOptions: github.ListOptions{PerPage: 10},
			}
			err = owner.fetchUserRepos(userOpt, gitClient, ctx)
		}
	}
	return err
}

// fetchOrgRepos used by fetchRepos is responsible for parsing github's org repo response. If no
// github token is available then fetchOrgRepos might run into a rate limit in which case owner will
// log an error and gitleaks will exit. The rate limit for no token is 50 req/hour... not much.
func (owner *Owner) fetchOrgRepos(orgOpts *github.RepositoryListByOrgOptions, gitClient *github.Client,
	ctx context.Context) error {
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
			logger.Info("hit rate limit")
		} else if err != nil {
			return fmt.Errorf("failed fetching org repos, bad request")
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
func (owner *Owner) fetchUserRepos(userOpts *github.RepositoryListOptions, gitClient *github.Client,
	ctx context.Context) error {
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
			logger.Info("hit rate limit")
			break
		} else if err != nil {
			return fmt.Errorf("failed fetching user repos, bad request")
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
		owner.repos = append(owner.repos, *newRepo(*repo.Name, *repo.CloneURL))
	}
}

// auditRepos
func (owner *Owner) auditRepos() (int) {
	exitCode := EXIT_CLEAN
	for _, repo := range owner.repos {
		leaksPst, err := repo.audit(owner)
		if err != nil {
			failF("%v\n", err)
		}
		if leaksPst{
			exitCode = EXIT_LEAKS
		}
	}
	return exitCode
}

// failF prints a failure message out to stderr
// and exits with a exit code 2
func (owner *Owner) failF(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(EXIT_FAILURE)
}

// setupDir sets up the owner's directory for clones and reports.
// If the temporary option is set then a temporary directory will be
// used for the owner repo clones.
func (owner *Owner) setupDir() error {
	if opts.Tmp {
		dir, err := ioutil.TempDir("", owner.name)
		if err != nil {
			return err
			owner.failF("Unabled to create temp directories for cloning")
		}
		owner.path = dir
	} else {
		if _, err := os.Stat(opts.ClonePath); os.IsNotExist(err) {
			os.Mkdir(owner.path, os.ModePerm)
		}
	}
	return nil

	// TODO could be handled via option
	// owner.reportPath = filepath.Join(gitLeaksPath, "report", owner.name)
}

// rmTmp removes the temporary repo
func (owner *Owner) rmTmp() {
	os.RemoveAll(owner.path)
	os.Exit(EXIT_FAILURE)
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
func ownerName() (string) {
	if opts.RepoMode {
		splitSlashes := strings.Split(opts.URL, "/")
		return splitSlashes[len(splitSlashes)-2]
	} else if opts.UserMode|| opts.OrgMode {
		_, ownerName := path.Split(opts.URL)
		return ownerName
	}
	// local repo
	return ""
}

// githubTokenClient creates an oauth client from your github access token.
// Gitleaks will attempt to retrieve your github access token from a cli argument
// or an env var - "GITHUB_TOKEN".
// Might be good to eventually parse the token from a Config or creds file in
// $GITLEAKS_HOME
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
