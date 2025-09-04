package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v71/github"
	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/logging"
	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"
)

var (
	reposCmd = &cobra.Command{
		Use:   "repos [flags]",
		Short: "scan remote account repos for secrets",
		Run:   runRepos,
		Example: `- gitleaks repos -u userName 					# scans the 5 most recently updated repos for userName
- gitleaks repos -u userName --repo repoName 			# scans a specific repo for userName
- gitleaks repos -u orgName -t org --include-forks --include-archived --limit 10 --threads 10
- GITHUB_TOKEN=yourtoken gitleaks repos -u orgName -t org --limit 0 --threads 20 --output-dir my-reports --cleanup-repos
		`,
	}
	accountType     string
	username        string
	repo            string
	limit           int
	threads         int
	includeForks    bool
	includeArchived bool
	outputDir       string
	cloneDepth      int
	cloneTimeout    time.Duration
	scanTimeout     time.Duration
	cleanupRepos    bool
)

func init() {
	rootCmd.AddCommand(reposCmd)
	reposCmd.Flags().StringVarP(&accountType, "type", "t", "user", "The type of account to scan (user, org)")
	reposCmd.Flags().StringVarP(&username, "username", "u", "", "The username of the user or org account to scan")
	reposCmd.Flags().StringVarP(&repo, "repo", "", "", "The specific repository to scan (overrides username and type)")
	reposCmd.Flags().IntVarP(&limit, "limit", "", 5, "number of repositories to scan (default 5; 0 means clone all repositories)")
	reposCmd.Flags().IntVarP(&threads, "threads", "", 5, "number of threads to use for the scan (default 5)")
	reposCmd.Flags().BoolVar(&includeForks, "include-forks", false, "Include forked repositories in the scan")
	reposCmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in the scan")
	reposCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "gitleaks-reports", "The directory to store the scan results")
	reposCmd.Flags().DurationVar(&cloneTimeout, "clone-timeout", 30*time.Second, "Timeout for cloning each repository (e.g., 30s, 1m)")
	reposCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 10*time.Minute, "Timeout for scanning each repository (e.g., 10m, 1h)")
	reposCmd.Flags().BoolVar(&cleanupRepos, "cleanup-repos", false, "Remove cloned repositories after scanning")
	reposCmd.Flags().IntVar(&cloneDepth, "clone-depth", 1, "Depth for git clone (default 1 for shallow clone)")
}

func runRepos(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if username == "" {
		logging.Fatal().Msg("username for account required")
	}
	if threads <= 0 {
		threads = 5
	}
	ghClient := createGitHubClient(ctx)
	repos, err := fetchRepos(ctx, ghClient)
	if err != nil {
		logging.Fatal().Msgf("Failed to fetch repositories: %v", err)
	}
	if len(repos) == 0 {
		logging.Warn().Msg("Found no repositories")
		return
	}
	logging.Info().Msgf("Found %d repositories. Starting scan...", len(repos))
	if err := setupDirectories(); err != nil {
		logging.Fatal().Msgf("Failed to setup directories: %v", err)
	}
	if err := scanRepos(ctx, repos); err != nil {
		logging.Fatal().Msgf("Scan failed: %v", err)
	}
	logging.Info().Msgf("All scans complete. Check %s/%s/", outputDir, username)
}

func createGitHubClient(ctx context.Context) *github.Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(ctx, ts)
		return github.NewClient(tc)
	}
	logging.Info().Msg("No GITHUB_TOKEN set. Scanning public repositories only (rate limit: 60/hour)")
	return github.NewClient(nil)
}

func fetchRepos(ctx context.Context, ghClient *github.Client) ([]*github.Repository, error) {
	var repos []*github.Repository
	logging.Info().Msg("Fetching repositories...")

	page := 1
	perPage := 100
	if limit > 0 && limit < perPage {
		perPage = limit
	}

	for {
		var pageRepos []*github.Repository
		var resp *github.Response
		var err error
		if repo != "" {
			r, _, err := ghClient.Repositories.Get(ctx, username, repo)
			if err != nil {
				return nil, fmt.Errorf("error fetching repository %s/%s: %w", username, repo, err)
			}
			pageRepos = append(pageRepos, r)
			resp = &github.Response{NextPage: 0}
		} else {
			if accountType == "org" {
				opts := &github.RepositoryListByOrgOptions{Type: "all", Sort: "updated", Direction: "desc", ListOptions: github.ListOptions{Page: page, PerPage: perPage}}
				pageRepos, resp, err = ghClient.Repositories.ListByOrg(ctx, username, opts)
			} else {
				opts := &github.RepositoryListByUserOptions{Type: "all", Sort: "updated", Direction: "desc", ListOptions: github.ListOptions{Page: page, PerPage: perPage}}
				pageRepos, resp, err = ghClient.Repositories.ListByUser(ctx, username, opts)
			}
			if err != nil {
				return nil, fmt.Errorf("error fetching repositories page %d: %w", page, err)
			}
		}

		for _, r := range pageRepos {
			if !includeArchived && r.GetArchived() {
				continue
			}
			if !includeForks && r.GetFork() {
				continue
			}
			repos = append(repos, r)
			if limit > 0 && len(repos) >= limit {
				return repos, nil
			}
		}

		if resp == nil || resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}
	return repos, nil
}

func setupDirectories() error {
	userResultDir := filepath.Join(outputDir, username)
	dirs := []string{userResultDir, filepath.Join(userResultDir, "repos"), filepath.Join(userResultDir, "results")}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

func scanRepos(ctx context.Context, repos []*github.Repository) error {
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(int64(threads))
	reposDir := filepath.Join(filepath.Join(outputDir, username), "repos")
	resultsDir := filepath.Join(filepath.Join(outputDir, username), "results")
	for _, repo := range repos {
		wg.Add(1)
		go func(repo *github.Repository) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				logging.Error().Msgf("Failed to acquire semaphore: %v", err)
				return
			}
			defer sem.Release(1)

			url := repo.GetCloneURL()
			name := strings.ReplaceAll(strings.ReplaceAll(repo.GetName(), "/", "_"), " ", "_")
			repoDir := filepath.Join(reposDir, name)
			reportDir, err := filepath.Abs(resultsDir)
			if err != nil {
				logging.Error().Msgf("Failed to get absolute path for results directory: %v", err)
				return
			}
			reportPath := fmt.Sprintf("%s/%s.json", reportDir, name)
			logging.Info().Msgf("Processing repo: %s\n", name)

			cloneCtx, cancel := context.WithTimeout(ctx, cloneTimeout)
			cloneCmd := exec.CommandContext(cloneCtx, "git", "clone", "--depth", fmt.Sprintf("%d", cloneDepth), url, repoDir)
			cloneCmd.Stdout = nil
			cloneCmd.Stderr = nil
			if err := cloneCmd.Run(); err != nil {
				cancel()
				if cloneCtx.Err() == context.DeadlineExceeded {
					logging.Warn().Msgf("Cloning %s timed out after %s. Skipping this repository.", url, cloneTimeout)
					return
				}
				if err.Error() != "exit status 128" {
					logging.Error().Msgf("Failed to clone repository %s: %v", url, err)
				}
				return
			}
			cancel()

			scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
			gitleaksCmd := exec.CommandContext(scanCtx, "gitleaks", "git", "-r", reportPath, "--no-banner")
			gitleaksCmd.Dir = repoDir
			gitleaksCmd.Stdout = os.Stdout
			gitleaksCmd.Stderr = os.Stderr
			if err := gitleaksCmd.Run(); err != nil {
				cancel()
				if scanCtx.Err() == context.DeadlineExceeded {
					logging.Warn().Msgf("Scanning %s timed out after %s. Skipping this repository.", name, scanTimeout)
					return
				}
				logging.Error().Msgf("Failed to scan repository %s: %v", name, err)
				return
			}
			cancel()

			if cleanupRepos {
				defer func() {
					if err := os.RemoveAll(repoDir); err != nil {
						fmt.Printf("Warning: failed to cleanup %s: %v\n", repoDir, err)
					}
				}()
			}
		}(repo)
	}
	wg.Wait()
	return nil
}
