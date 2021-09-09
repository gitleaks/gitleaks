package options

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/zricethezav/gitleaks/v7/version"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

// Options stores values of command line options
type Options struct {
	Verbose          bool   `short:"v" long:"verbose" description:"Show verbose output from scan"`
	Quiet            bool   `short:"q" long:"quiet" description:"Sets log level to error and only output leaks, one json object per line"`
	RepoURL          string `short:"r" long:"repo-url" description:"Repository URL"`
	Path             string `short:"p" long:"path" description:"Path to directory (repo if contains .git) or file"`
	ConfigPath       string `short:"c" long:"config-path" description:"Path to config"`
	RepoConfigPath   string `long:"repo-config-path" description:"Path to gitleaks config relative to repo root"`
	ClonePath        string `long:"clone-path" description:"Path to clone repo to disk"`
	Version          bool   `long:"version" description:"Version number"`
	Username         string `long:"username" description:"Username for git repo"`
	Password         string `long:"password" description:"Password for git repo"`
	AccessToken      string `long:"access-token" description:"Access token for git repo"`
	Threads          int    `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	SSH              string `long:"ssh-key" description:"Path to ssh key used for auth"`
	Unstaged         bool   `long:"unstaged" description:"Run gitleaks on unstaged code"`
	Branch           string `long:"branch" description:"Branch to scan"`
	Redact           bool   `long:"redact" description:"Redact secrets from log messages and leaks"`
	Debug            bool   `long:"debug" description:"Log debug messages"`
	NoGit            bool   `long:"no-git" description:"Treat git repos as plain directories and scan those files"`
	CodeOnLeak       int    `long:"leaks-exit-code" default:"1" description:"Exit code when leaks have been encountered"`
	AppendRepoConfig bool   `long:"append-repo-config" description:"Append the provided or default config with the repo config."`
	AdditionalConfig string `long:"additional-config" description:"Path to an additional gitleaks config to append with an existing config. Can be used with --append-repo-config to append up to three configurations"`

	// Report Options
	Report       string `short:"o" long:"report" description:"Report output path"`
	ReportFormat string `short:"f" long:"format" default:"json" description:"json, csv, sarif"`

	// Commit Options
	FilesAtCommit string `long:"files-at-commit" description:"Sha of commit to scan all files at commit"`
	Commit        string `long:"commit" description:"Sha of commit to scan or \"latest\" to scan the last commit of the repository"`
	Commits       string `long:"commits" description:"Comma separated list of a commits to scan"`
	CommitsFile   string `long:"commits-file" description:"Path to file of line separated list of commits to scan"`
	CommitFrom    string `long:"commit-from" description:"Commit to start scan from"`
	CommitTo      string `long:"commit-to" description:"Commit to stop scan"`
	CommitSince   string `long:"commit-since" description:"Scan commits more recent than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format."`
	CommitUntil   string `long:"commit-until" description:"Scan commits older than a specific date. Ex: '2006-01-02' or '2006-01-02T15:04:05-0700' format."`
	Depth         int    `long:"depth" description:"Number of commits to scan"`
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
		os.Exit(1)
	}

	if opts.Version {
		if version.Version == "" {
			fmt.Println("Gitleaks uses LDFLAGS to pull most recent version. Build with 'make build' for version")
		} else {
			fmt.Printf("%s\n", version.Version)
		}
		os.Exit(0)
	}

	if opts.Debug {
		log.SetLevel(log.DebugLevel)
	}
	if opts.Quiet {
		log.SetLevel(log.ErrorLevel)
	}

	return opts, nil
}

// Guard checks to makes sure there are no invalid options set.
// If invalid sets of options are present, a descriptive error will return
// else nil is returned
func (opts Options) Guard() error {
	if !oneOrNoneSet(opts.RepoURL, opts.Path) {
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
	var err error
	progress := ioutil.Discard
	if opts.Verbose {
		progress = os.Stdout
	}

	cloneOpts := &git.CloneOptions{
		URL:      opts.RepoURL,
		Progress: progress,
	}
	if opts.Depth != 0 {
		cloneOpts.Depth = opts.Depth
	}
	if opts.Branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(opts.Branch)
	}

	var auth transport.AuthMethod

	if strings.HasPrefix(opts.RepoURL, "ssh://") || (!strings.Contains(opts.RepoURL, "://") && strings.Contains(opts.RepoURL, ":")) {
		// using ssh:// url or scp-like syntax
		auth, err = SSHAuth(opts)
		if err != nil {
			return nil, err
		}
	} else if opts.Password != "" && opts.Username != "" {
		// auth using username and password
		auth = &http.BasicAuth{
			Username: opts.Username,
			Password: opts.Password,
		}
	} else if opts.AccessToken != "" {
		auth = &http.BasicAuth{
			Username: "gitleaks_user",
			Password: opts.AccessToken,
		}
	} else if os.Getenv("GITLEAKS_ACCESS_TOKEN") != "" {
		auth = &http.BasicAuth{
			Username: "gitleaks_user",
			Password: os.Getenv("GITLEAKS_ACCESS_TOKEN"),
		}
	}
	if auth != nil {
		cloneOpts.Auth = auth
	}
	return cloneOpts, nil
}

// SSHAuth tried to generate ssh public keys based on what was passed via cli. If no
// path was passed via cli then this will attempt to retrieve keys from the default
// location for ssh keys, $HOME/.ssh/id_rsa. This function is only called if the
// repo url using the ssh:// protocol or scp-like syntax.
func SSHAuth(opts Options) (*ssh.PublicKeys, error) {
	params := strings.Split(opts.RepoURL, "@")

	if len(params) != 2 {
		return nil, fmt.Errorf("user must be specified in the URL")
	}

	// the part of the RepoURL before the "@" (params[0]) can be something like:
	// - "ssh://user" if RepoURL is an ssh:// URL
	// - "user" if RepoURL uses scp-like syntax
	// we must strip the protocol if it is present so that we only have "user"
	username := strings.Replace(params[0], "ssh://", "", 1)

	if opts.SSH != "" {
		return ssh.NewPublicKeysFromFile(username, opts.SSH, "")
	}
	c, err := user.Current()
	if err != nil {
		return nil, err
	}
	defaultPath := fmt.Sprintf("%s/.ssh/id_rsa", c.HomeDir)
	return ssh.NewPublicKeysFromFile(username, defaultPath, "")
}

// OpenLocal checks what options are set, if no remote targets are set
// then return true
func (opts Options) OpenLocal() bool {
	if opts.Unstaged || opts.Path != "" || opts.RepoURL == "" {
		return true
	}
	return false
}

// CheckUncommitted returns a boolean that indicates whether or not gitleaks should check unstaged pre-commit changes
// or if gitleaks should check the entire git history
func (opts Options) CheckUncommitted() bool {
	// check to make sure no remote shit is set
	if opts.Unstaged {
		return true
	}
	if opts == (Options{}) {
		return true
	}
	if opts.RepoURL != "" {
		return false
	}
	if opts.Path != "" {
		return false
	}
	return true
}
