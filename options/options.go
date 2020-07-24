package options

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/zricethezav/gitleaks/v5/version"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

// No leaks or early exit due to invalid options
// This block defines the exit codes. Success
const (
	// No leaks or early exit due to invalid options
	Success          = 0
	LeaksPresent     = 1
	ErrorEncountered = 2
	donateMessage    = "👋 maintaining gitleaks takes a lot of work so consider sponsoring me or donating a little something\n❤️ https://github.com/sponsors/zricethezav\n💸 https://www.paypal.me/zricethezav\n₿  btc:3GndEzRZa6rJ8ZpkLureUcc5TDHMYfpDxn"
)

// Options stores values of command line options
type Options struct {
	Verbose       bool   `short:"v" long:"verbose" description:"Show verbose output from scan"`
	Repo          string `short:"r" long:"repo" description:"Target repository"`
	Config        string `long:"config" description:"config path"`
	Disk          bool   `long:"disk" description:"Clones repo(s) to disk"`
	Version       bool   `long:"version" description:"version number"`
	Username      string `long:"username" description:"Username for git repo"`
	Password      string `long:"password" description:"Password for git repo"`
	AccessToken   string `long:"access-token" description:"Access token for git repo"`
	Commit        string `long:"commit" description:"sha of commit to scan or \"latest\" to scan the last commit of the repository"`
	FilesAtCommit string `long:"files-at-commit" description:"sha of commit to scan all files at commit"`
	Threads       int    `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	SSH           string `long:"ssh-key" description:"path to ssh key used for auth"`
	Uncommited    bool   `long:"uncommitted" description:"run gitleaks on uncommitted code"`
	RepoPath      string `long:"repo-path" description:"Path to repo"`
	OwnerPath     string `long:"owner-path" description:"Path to owner directory (repos discovered)"`
	Branch        string `long:"branch" description:"Branch to scan"`
	Report        string `long:"report" description:"path to write json leaks file"`
	ReportFormat  string `long:"report-format" default:"json" description:"json or csv"`
	Redact        bool   `long:"redact" description:"redact secrets from log messages and leaks"`
	Debug         bool   `long:"debug" description:"log debug messages"`
	RepoConfig    bool   `long:"repo-config" description:"Load config from target repo. Config file must be \".gitleaks.toml\" or \"gitleaks.toml\""`
	PrettyPrint   bool   `long:"pretty" description:"Pretty print json if leaks are present"`
	CommitFrom    string `long:"commit-from" description:"Commit to start scan from"`
	CommitTo      string `long:"commit-to" description:"Commit to stop scan"`
	CommitSince   string `long:"commit-since" description:"Scan commits more recent than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format."`
	CommitUntil   string `long:"commit-until" description:"Scan commits older than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format."`
	Timeout       string `long:"timeout" description:"Time allowed per scan. Ex: 10us, 30s, 1m, 1h10m1s"`
	Depth         int    `long:"depth" description:"Number of commits to scan"`
	Deletion      bool   `long:"include-deletion" description:"Scan for patch deletions in addition to patch additions"`

	// Hosts
	Host         string `long:"host" description:"git hosting service like gitlab or github. Supported hosts include: Github, Gitlab"`
	BaseURL      string `long:"baseurl" description:"Base URL for API requests. Defaults to the public GitLab or GitHub API, but can be set to a domain endpoint to use with a self hosted server."`
	Organization string `long:"org" description:"organization to scan"`
	User         string `long:"user" description:"user to scan"`
	PullRequest  string `long:"pr" description:"pull/merge request url"`
	ExcludeForks bool   `long:"exclude-forks" description:"scan excludes forks"`
}

// ParseOptions is responsible for parsing options passed in by cli. An Options struct
// is returned if successful. This struct is passed around the program
// and will determine how the program executes. If err, an err message or help message
// will be displayed and the program will exit with code 0.
func ParseOptions() (Options, error) {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stdout)
		}
		fmt.Println(donateMessage)
		os.Exit(0)
	}

	if opts.Version {
		if version.Version == "" {
			fmt.Println("Gitleaks uses LDFLAGS to pull most recent version. Build with 'make build' for version")
		} else {
			fmt.Printf("%s\n", version.Version)
		}
		os.Exit(Success)
	}

	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}

	return opts, nil
}

// Guard checks to makes sure there are no invalid options set.
// If invalid sets of options are present, a descriptive error will return
// else nil is returned
func (opts Options) Guard() error {
	if !oneOrNoneSet(opts.Repo, opts.OwnerPath, opts.RepoPath, opts.Host) {
		return fmt.Errorf("only one target option must can be set. target options: repo, owner-path, repo-path, host")
	}
	if !oneOrNoneSet(opts.Organization, opts.User, opts.PullRequest) {
		return fmt.Errorf("only one target option must can be set. target options: repo, owner-path, repo-path, host")
	}
	if !oneOrNoneSet(opts.AccessToken, opts.Password) {
		log.Warn("both access-token and password are set. Only password will be attempted")
	}

	return nil
}

func oneOrNoneSet(optStr ...string) bool {
	c := 0
	for _, s := range optStr {
		if s != "" {
			c++
		}
	}
	if c <= 1 {
		return true
	}
	return false
}

// CloneOptions returns a git.cloneOptions pointer. The authentication method
// is determined by what is passed in via command-Line options. If No
// Username/PW or AccessToken is available and the repo target is not using the
// git protocol then the repo must be a available via no auth.
func (opts Options) CloneOptions() (*git.CloneOptions, error) {
	progress := ioutil.Discard
	if opts.Verbose {
		progress = os.Stdout
	}

	if strings.HasPrefix(opts.Repo, "git") {
		// using git protocol so needs ssh auth
		auth, err := SSHAuth(opts)
		if err != nil {
			return nil, err
		}
		return &git.CloneOptions{
			URL:      opts.Repo,
			Auth:     auth,
			Progress: progress,
		}, nil
	}
	if opts.Password != "" && opts.Username != "" {
		// auth using username and password
		return &git.CloneOptions{
			URL: opts.Repo,
			Auth: &http.BasicAuth{
				Username: opts.Username,
				Password: opts.Password,
			},
			Progress: progress,
		}, nil
	}
	if opts.AccessToken != "" {
		return &git.CloneOptions{
			URL: opts.Repo,
			Auth: &http.BasicAuth{
				Username: "gitleaks_user",
				Password: opts.AccessToken,
			},
			Progress: progress,
		}, nil
	}
	if os.Getenv("GITLEAKS_ACCESS_TOKEN") != "" {
		return &git.CloneOptions{
			URL: opts.Repo,
			Auth: &http.BasicAuth{
				Username: "gitleaks_user",
				Password: os.Getenv("GITLEAKS_ACCESS_TOKEN"),
			},
			Progress: progress,
		}, nil
	}

	// No Auth, publicly available
	return &git.CloneOptions{
		URL:      opts.Repo,
		Progress: progress,
	}, nil
}

// SSHAuth tried to generate ssh public keys based on what was passed via cli. If no
// path was passed via cli then this will attempt to retrieve keys from the default
// location for ssh keys, $HOME/.ssh/id_rsa. This function is only called if the
// repo url using the git:// protocol.
func SSHAuth(opts Options) (*ssh.PublicKeys, error) {
	if opts.SSH != "" {
		return ssh.NewPublicKeysFromFile("git", opts.SSH, "")
	}
	c, err := user.Current()
	if err != nil {
		return nil, err
	}
	defaultPath := fmt.Sprintf("%s/.ssh/id_rsa", c.HomeDir)
	return ssh.NewPublicKeysFromFile("git", defaultPath, "")
}

// OpenLocal checks what options are set, if no remote targets are set
// then return true
func (opts Options) OpenLocal() bool {
	if opts.Uncommited || opts.RepoPath != "" || opts.Repo == "" {
		return true
	}
	return false
}

// CheckUncommitted returns a boolean that indicates whether or not gitleaks should check unstaged pre-commit changes
// or if gitleaks should check the entire git history
func (opts Options) CheckUncommitted() bool {
	// check to make sure no remote shit is set
	if opts.Uncommited {
		return true
	}
	if opts == (Options{}) {
		return true
	}
	if opts.Repo != "" {
		return false
	}
	if opts.RepoPath != "" {
		return false
	}
	if opts.OwnerPath != "" {
		return false
	}
	if opts.Host != "" {
		return false
	}
	return true
}

// GetAccessToken accepts options and returns a string which is the access token to a git host.
// Setting this option or environment var is necessary if performing an scan with any of the git hosting providers
// in the host pkg. The access token set by cli options takes precedence over env vars.
func GetAccessToken(opts Options) string {
	if opts.AccessToken != "" {
		return opts.AccessToken
	}
	return os.Getenv("GITLEAKS_ACCESS_TOKEN")
}
