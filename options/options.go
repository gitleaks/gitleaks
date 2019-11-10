package options

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/zricethezav/gitleaks-ng/version"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
	"io/ioutil"
	"os"
	"os/user"
	"strings"
)

const (
	Success int = iota + 1
	LeaksPresent
	ErrorEncountered
)

type Options struct {
	Verbose     bool   `short:"v" long:"verbose" description:"Show verbose output from audit"`
	Repo        string `short:"r" long:"repo" description:"Target repository"`
	Config      string `long:"config" description:"config path"`
	Disk        bool   `long:"disk" description:"Clones repo(s) to disk"`
	Version     bool   `long:"version" description:"version number"`
	Timeout     int    `long:"timeout" description:"Timeout (s)"`
	Username    string `long:"username" description:"Username for git repo"`
	Password    string `long:"password" description:"Password for git repo"`
	AccessToken string `long:"access-token" description:"Access token for git repo"`
	Commit      string `long:"commit" description:"sha of commit to audit"`
	Threads     int    `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	SSH         string `long:"ssh-key" description:"path to ssh key used for auth"`
	Uncommited  bool   `long:"uncommitted" description:"run gitleaks on uncommitted code"`
	RepoPath    string `long:"repo-path" description:"Path to repo"`
	OwnerPath   string `long:"owner-path" description:"Path to owner directory (repos discovered)"`
	Branch      string `long:"branch" description:"Branch to audit"`
	Report      string `long:"report" description:"path to write json leaks file"`
	Redact      bool   `long:"redact" description:"redact secrets from log messages and leaks"`
	Debug       bool   `long:"debug" description:"log debug messages"`
	RepoConfig   bool   `long:"repo-config" description:"Load config from target repo. Config file must be \".gitleaks.toml\" or \"gitleaks.toml\""`

	// Hosts
	Host         string `long:"host" description:"git hosting service like gitlab or github. Supported hosts include: Github, Gitlab"`
	Organization string `long:"org" description:"organization to audit"`
	User         string `long:"user" description:"user to audit"` //work
	PullRequest  string `long:"pr" description:"pull/merge request url"`
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
		parser.WriteHelp(os.Stdout)
		os.Exit(Success)
	}

	if opts.Version {
		fmt.Printf("%s\n", version.Version)
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
	// 1. only one target option set at a time:
	// repo, owner-path, repo-path
	return nil
}

// cloneOptions returns a git.cloneOptions pointer. The authentication method
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
		auth, err := sshAuth(opts)
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

// sshAuth tried to generate ssh public keys based on what was passed via cli. If no
// path was passed via cli then this will attempt to retrieve keys from the default
// location for ssh keys, $HOME/.ssh/id_rsa. This function is only called if the
// repo url using the git:// protocol.
func sshAuth(opts Options) (*ssh.PublicKeys, error) {
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

// openLocal checks what options are set, if no remote targets are set
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
// Setting this option or environment var is necessary if performing an audit with any of the git hosting providers
// in the host pkg. The access token set by cli options takes precedence over env vars.
func GetAccessToken(opts Options) string {
	if opts.AccessToken != "" {
		return opts.AccessToken
	}
	return os.Getenv("GITLEAKS_ACCESS_TOKEN")
}
