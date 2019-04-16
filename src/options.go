package gitleaks

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
)

// Options for gitleaks
type Options struct {
	// remote target options
	Repo       string `short:"r" long:"repo" description:"Repo url to audit"`
	GithubUser string `long:"github-user" description:"Github user to audit"`
	GithubOrg  string `long:"github-org" description:"Github organization to audit"`
	GithubURL  string `long:"github-url" default:"https://api.github.com/" description:"GitHub API Base URL, use for GitHub Enterprise. Example: https://github.example.com/api/v3/"`
	GithubPR   string `long:"github-pr" description:"Github PR url to audit. This does not clone the repo. GITHUB_TOKEN must be set"`

	GitLabUser string `long:"gitlab-user" description:"GitLab user ID to audit"`
	GitLabOrg  string `long:"gitlab-org" description:"GitLab group ID to audit"`

	CommitStop string `long:"commit-stop" description:"sha of commit to stop at"`
	Commit     string `long:"commit" description:"sha of commit to audit"`
	Depth      int64  `long:"depth" description:"maximum commit depth"`

	// local target option
	RepoPath  string `long:"repo-path" description:"Path to repo"`
	OwnerPath string `long:"owner-path" description:"Path to owner directory (repos discovered)"`

	// Process options
	Threads      int    `long:"threads" description:"Maximum number of threads gitleaks spawns"`
	Disk         bool   `long:"disk" description:"Clones repo(s) to disk"`
	ConfigPath   string `long:"config" description:"path to gitleaks config"`
	SSHKey       string `long:"ssh-key" description:"path to ssh key"`
	ExcludeForks bool   `long:"exclude-forks" description:"exclude forks for organization/user audits"`
	RepoConfig   bool   `long:"repo-config" description:"Load config from target repo. Config file must be \".gitleaks.toml\""`
	Branch       string `long:"branch" description:"Branch to audit"`
	// TODO: IncludeMessages  string `long:"messages" description:"include commit messages in audit"`

	// Output options
	Log          string `short:"l" long:"log" description:"log level"`
	Verbose      bool   `short:"v" long:"verbose" description:"Show verbose output from gitleaks audit"`
	Report       string `long:"report" description:"path to write report file. Needs to be csv or json"`
	Redact       bool   `long:"redact" description:"redact secrets from log messages and report"`
	Version      bool   `long:"version" description:"version number"`
	SampleConfig bool   `long:"sample-config" description:"prints a sample config file"`
}

// ParseOpts parses the options
func ParseOpts() *Options {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stdout)
		}
		os.Exit(0)
	}

	if len(os.Args) == 1 {
		parser.WriteHelp(os.Stdout)
		os.Exit(0)
	}

	if opts.Version {
		fmt.Println(version)
		os.Exit(0)
	}
	if opts.SampleConfig {
		fmt.Println(defaultConfig)
		os.Exit(0)
	}

	opts.setLogs()

	err = opts.guard()
	if err != nil {
		log.Fatal(err)
	}
	return &opts
}

// optsGuard prevents invalid options
func (opts *Options) guard() error {
	if opts.GithubOrg != "" && opts.GithubUser != "" {
		return fmt.Errorf("github user and organization set")
	} else if opts.GithubOrg != "" && opts.OwnerPath != "" {
		return fmt.Errorf("github organization set and local owner path")
	} else if opts.GithubUser != "" && opts.OwnerPath != "" {
		return fmt.Errorf("github user set and local owner path")
	}

	if opts.Threads > runtime.GOMAXPROCS(0) {
		return fmt.Errorf("%d available threads", runtime.GOMAXPROCS(0))
	}

	// do the URL Parse and error checking here, so we can skip it later
	// empty string is OK, it will default to the public github URL.
	if opts.GithubURL != "" && opts.GithubURL != defaultGithubURL {
		if !strings.HasSuffix(opts.GithubURL, "/") {
			opts.GithubURL += "/"
		}
		ghURL, err := url.Parse(opts.GithubURL)
		if err != nil {
			return err
		}
		tcpPort := "443"
		if ghURL.Scheme == "http" {
			tcpPort = "80"
		}
		timeout := time.Duration(1 * time.Second)
		_, err = net.DialTimeout("tcp", ghURL.Host+":"+tcpPort, timeout)
		if err != nil {
			return fmt.Errorf("%s unreachable, error: %s", ghURL.Host, err)
		}
	}

	if opts.Report != "" {
		if !strings.HasSuffix(opts.Report, ".json") && !strings.HasSuffix(opts.Report, ".csv") {
			return fmt.Errorf("Report should be a .json or .csv file")
		}
		dirPath := filepath.Dir(opts.Report)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist", dirPath)
		}
	}

	return nil
}

// setLogLevel sets log level for gitleaks. Default is Warning
func (opts *Options) setLogs() {
	switch opts.Log {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
}
