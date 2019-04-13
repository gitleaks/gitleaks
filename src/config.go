package gitleaks

import (
	"fmt"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/ssh"
)

type entropyRange struct {
	v1 float64
	v2 float64
}

// Rule instructs how gitleaks should audit each line of code
type Rule struct {
	description string
	regex       *regexp.Regexp
	severity    string
	tags        []string
	entropies   []*entropyRange
	entropyROI  string
}

// TomlConfig is used for loading gitleaks configs from a toml file
type TomlConfig struct {
	Rules []struct {
		Description string
		Regex       string
		Entropies   []string
		Tags        []string
		Severity    string
		EntropyROI  string
	}
	Whitelist struct {
		Files   []string
		Regexes []string
		Commits []string
		Repos   []string
	}
}

// Config contains gitleaks config
type Config struct {
	Rules     []*Rule
	WhiteList struct {
		regexes []*regexp.Regexp
		files   []*regexp.Regexp
		commits map[string]bool
		repos   []*regexp.Regexp
	}
	sshAuth *ssh.PublicKeys
}

// loadToml loads of the toml config containing regexes and whitelists.
// This function will first look if the configPath is set and load the config
// from that file. Otherwise will then look for the path set by the GITHLEAKS_CONIFG
// env var. If that is not set, then gitleaks will continue with the default configs
// specified by the const var at the top `defaultConfig`
func newConfig() (*Config, error) {
	var (
		tomlConfig TomlConfig
		configPath string
		config     Config
	)

	if opts.ConfigPath != "" {
		configPath = opts.ConfigPath
		_, err := os.Stat(configPath)
		if err != nil {
			return nil, fmt.Errorf("no gitleaks config at %s", configPath)
		}
	} else {
		configPath = os.Getenv("GITLEAKS_CONFIG")
	}

	if configPath != "" {
		if _, err := toml.DecodeFile(configPath, &tomlConfig); err != nil {
			return nil, fmt.Errorf("problem loading config: %v", err)
		}
	} else {
		_, err := toml.Decode(defaultConfig, &tomlConfig)
		if err != nil {
			return nil, fmt.Errorf("problem loading default config: %v", err)
		}
	}

	sshAuth, err := getSSHAuth()
	if err != nil {
		return nil, err
	}
	config.sshAuth = sshAuth

	err = config.update(tomlConfig)
	if err != nil {
		return nil, err
	}
	return &config, err
}

// updateConfig will update a the global config values
func (config *Config) update(tomlConfig TomlConfig) error {
	for _, rule := range tomlConfig.Rules {
		re := regexp.MustCompile(rule.Regex)
		ranges, err := getEntropyRanges(rule.Entropies)
		if err != nil {
			log.Errorf("could not create entropy range for %s, skipping rule", rule.Description)
			continue
		}
		r := &Rule{
			description: rule.Description,
			regex:       re,
			severity:    rule.Severity,
			tags:        rule.Tags,
			entropies:   ranges,
			entropyROI:  rule.EntropyROI,
		}
		config.Rules = append(config.Rules, r)
	}

	// set whitelists
	config.WhiteList.commits = make(map[string]bool)
	for _, commit := range tomlConfig.Whitelist.Commits {
		config.WhiteList.commits[commit] = true
	}
	for _, regex := range tomlConfig.Whitelist.Files {
		config.WhiteList.files = append(config.WhiteList.files, regexp.MustCompile(regex))
	}
	for _, regex := range tomlConfig.Whitelist.Regexes {
		config.WhiteList.regexes = append(config.WhiteList.regexes, regexp.MustCompile(regex))
	}
	for _, regex := range tomlConfig.Whitelist.Repos {
		config.WhiteList.repos = append(config.WhiteList.repos, regexp.MustCompile(regex))
	}

	return nil
}

// entropyRanges hydrates entropyRanges which allows for fine tuning entropy checking
func getEntropyRanges(entropyLimitStr []string) ([]*entropyRange, error) {
	var ranges []*entropyRange
	for _, span := range entropyLimitStr {
		split := strings.Split(span, "-")
		v1, err := strconv.ParseFloat(split[0], 64)
		if err != nil {
			return nil, err
		}
		v2, err := strconv.ParseFloat(split[1], 64)
		if err != nil {
			return nil, err
		}
		if v1 > v2 {
			return nil, fmt.Errorf("entropy range must be ascending")
		}
		r := &entropyRange{
			v1: v1,
			v2: v2,
		}
		if r.v1 > 8.0 || r.v1 < 0.0 || r.v2 > 8.0 || r.v2 < 0.0 {
			return nil, fmt.Errorf("invalid entropy ranges, must be within 0.0-8.0")
		}
		ranges = append(ranges, r)
	}
	return ranges, nil
}

// externalConfig will attempt to load a pinned ".gitleaks.toml" configuration file
// from a remote or local repo. Use the --repo-config option to trigger this.
func (config *Config) updateFromRepo(repo *RepoInfo) error {
	var tomlConfig TomlConfig
	wt, err := repo.repository.Worktree()
	if err != nil {
		return err
	}
	f, err := wt.Filesystem.Open(".gitleaks.toml")
	if err != nil {
		return err
	}
	if _, err := toml.DecodeReader(f, &config); err != nil {
		return fmt.Errorf("problem loading config: %v", err)
	}
	f.Close()
	if err != nil {
		return err
	}
	return config.update(tomlConfig)
}

// getSSHAuth return an ssh auth use by go-git to clone repos behind authentication.
// If --ssh-key is set then it will attempt to load the key from that path. If not,
// gitleaks will use the default $HOME/.ssh/id_rsa key
func getSSHAuth() (*ssh.PublicKeys, error) {
	var (
		sshKeyPath string
	)
	if opts.SSHKey != "" {
		sshKeyPath = opts.SSHKey
	} else {
		// try grabbing default
		c, err := user.Current()
		if err != nil {
			return nil, nil
		}
		sshKeyPath = fmt.Sprintf("%s/.ssh/id_rsa", c.HomeDir)
	}
	sshAuth, err := ssh.NewPublicKeysFromFile("git", sshKeyPath, "")
	if err != nil {
		if strings.HasPrefix(opts.Repo, "git") {
			// if you are attempting to clone a git repo via ssh and supply a bad ssh key,
			// the clone will fail.
			return nil, fmt.Errorf("unable to generate ssh key: %v", err)
		}
	}
	return sshAuth, nil
}
