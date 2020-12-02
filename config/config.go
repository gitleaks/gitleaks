package config

import (
	"fmt"
	"path"
	"regexp"
	"strconv"

	"github.com/zricethezav/gitleaks/v7/options"

	"github.com/BurntSushi/toml"
	"github.com/go-git/go-git/v5"
	log "github.com/sirupsen/logrus"
)

// AllowList is struct containing items that if encountered will allowlist
// a commit/line of code that would be considered a leak.
type AllowList struct {
	Description string
	Regexes     []*regexp.Regexp
	Commits     []string
	Files       []*regexp.Regexp
	Paths       []*regexp.Regexp
	Repos       []*regexp.Regexp
}

// Entropy represents an entropy range
type Entropy struct {
	Min   float64
	Max   float64
	Group int
}

// Rule is a struct that contains information that is loaded from a gitleaks config.
// This struct is used in the Config struct as an array of Rules and is iterated
// over during an scan. Each rule will be checked. If a regex match is found AND
// that match is not allowlisted (globally or locally), then a leak will be appended
// to the final scan report.
type Rule struct {
	Description string
	Regex       *regexp.Regexp
	File        *regexp.Regexp
	Path        *regexp.Regexp
	ReportGroup int
	Tags        []string
	AllowList   AllowList
	Entropies   []Entropy
}

// Config is a composite struct of Rules and Allowlists
// Each Rule contains a description, regular expression, tags, and allowlists if available
type Config struct {
	Rules     []Rule
	Allowlist AllowList
}

// TomlAllowList is a struct used in the TomlLoader that loads in allowlists from
// specific rules or globally at the top level config
type TomlAllowList struct {
	Description string
	Regexes     []string
	Commits     []string
	Files       []string
	Paths       []string
	Repos       []string
}

// TomlLoader gets loaded with the values from a gitleaks toml config
// see the config in config/defaults.go for an example. TomlLoader is used
// to generate Config values (compiling regexes, etc).
type TomlLoader struct {
	AllowList TomlAllowList
	Rules     []struct {
		Description string
		Regex       string
		File        string
		Path        string
		ReportGroup int
		Tags        []string
		Entropies   []struct {
			Min   string
			Max   string
			Group string
		}
		AllowList TomlAllowList
	}
}

// NewConfig will create a new config struct which contains
// rules on how gitleaks will proceed with its scan.
// If no options are passed via cli then NewConfig will return
// a default config which can be seen in config.go
func NewConfig(options options.Options) (Config, error) {
	var cfg Config
	tomlLoader := TomlLoader{}

	var err error
	if options.ConfigPath != "" {
		_, err = toml.DecodeFile(options.ConfigPath, &tomlLoader)
		// append a allowlist rule for allowlisting the config
		tomlLoader.AllowList.Files = append(tomlLoader.AllowList.Files, path.Base(options.ConfigPath))
	} else {
		_, err = toml.Decode(DefaultConfig, &tomlLoader)
	}
	if err != nil {
		return cfg, err
	}

	cfg, err = tomlLoader.Parse()
	if err != nil {
		return cfg, err
	}

	return cfg, nil
}

// Parse will parse the values set in a TomlLoader and use those values
// to create compiled regular expressions and rules used in scans
func (tomlLoader TomlLoader) Parse() (Config, error) {
	var cfg Config
	for _, rule := range tomlLoader.Rules {
		// check and make sure the rule is valid
		if rule.Regex == "" && rule.Path == "" && rule.File == "" && len(rule.Entropies) == 0 {
			log.Warnf("Rule %s does not define any actionable data", rule.Description)
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		fileNameRe, err := regexp.Compile(rule.File)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		filePathRe, err := regexp.Compile(rule.Path)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}

		// rule specific allowlists
		var allowList AllowList

		allowList.Description = rule.AllowList.Description

		// rule specific regexes
		for _, re := range rule.AllowList.Regexes {
			allowListedRegex, err := regexp.Compile(re)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			allowList.Regexes = append(allowList.Regexes, allowListedRegex)
		}

		// rule specific filenames
		for _, re := range rule.AllowList.Files {
			allowListedRegex, err := regexp.Compile(re)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			allowList.Files = append(allowList.Files, allowListedRegex)
		}

		// rule specific paths
		for _, re := range rule.AllowList.Paths {
			allowListedRegex, err := regexp.Compile(re)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			allowList.Paths = append(allowList.Paths, allowListedRegex)
		}

		// rule specific commits
		allowList.Commits = rule.AllowList.Commits

		var entropies []Entropy
		for _, e := range rule.Entropies {
			min, err := strconv.ParseFloat(e.Min, 64)
			if err != nil {
				return cfg, err
			}
			max, err := strconv.ParseFloat(e.Max, 64)
			if err != nil {
				return cfg, err
			}
			if e.Group == "" {
				e.Group = "0"
			}
			group, err := strconv.ParseInt(e.Group, 10, 64)
			if err != nil {
				return cfg, err
			} else if int(group) >= len(re.SubexpNames()) {
				return cfg, fmt.Errorf("problem loading config: group cannot be higher than number of groups in regexp")
			} else if group < 0 {
				return cfg, fmt.Errorf("problem loading config: group cannot be lower than 0")
			} else if min > 8.0 || min < 0.0 || max > 8.0 || max < 0.0 {
				return cfg, fmt.Errorf("problem loading config: invalid entropy ranges, must be within 0.0-8.0")
			} else if min > max {
				return cfg, fmt.Errorf("problem loading config: entropy Min value cannot be higher than Max value")
			}

			entropies = append(entropies, Entropy{Min: min, Max: max, Group: int(group)})
		}

		r := Rule{
			Description: rule.Description,
			Regex:       re,
			File:        fileNameRe,
			Path:        filePathRe,
			ReportGroup: rule.ReportGroup,
			Tags:        rule.Tags,
			AllowList:   allowList,
			Entropies:   entropies,
		}

		cfg.Rules = append(cfg.Rules, r)
	}

	// global regex allowLists
	for _, allowListRegex := range tomlLoader.AllowList.Regexes {
		re, err := regexp.Compile(allowListRegex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Regexes = append(cfg.Allowlist.Regexes, re)
	}

	// global file name allowLists
	for _, allowListFileName := range tomlLoader.AllowList.Files {
		re, err := regexp.Compile(allowListFileName)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Files = append(cfg.Allowlist.Files, re)
	}

	// global file path allowLists
	for _, allowListFilePath := range tomlLoader.AllowList.Paths {
		re, err := regexp.Compile(allowListFilePath)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Paths = append(cfg.Allowlist.Paths, re)
	}

	// global repo allowLists
	for _, allowListRepo := range tomlLoader.AllowList.Repos {
		re, err := regexp.Compile(allowListRepo)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Repos = append(cfg.Allowlist.Repos, re)
	}

	cfg.Allowlist.Commits = tomlLoader.AllowList.Commits
	cfg.Allowlist.Description = tomlLoader.AllowList.Description

	return cfg, nil
}

// LoadRepoConfig accepts a repo and config path related to the target repo's root.
func LoadRepoConfig(repo *git.Repository, repoConfig string) (Config, error) {
	gitRepoConfig, err := repo.Config()
	if err != nil {
		return Config{}, err
	}
	if !gitRepoConfig.Core.IsBare {
		wt, err := repo.Worktree()
		if err != nil {
			return Config{}, err
		}
		_, err = wt.Filesystem.Stat(repoConfig)
		if err != nil {
			return Config{}, err
		}
		r, err := wt.Filesystem.Open(repoConfig)
		if err != nil {
			return Config{}, err
		}
		var tomlLoader TomlLoader
		_, err = toml.DecodeReader(r, &tomlLoader)
		if err != nil {
			return Config{}, err
		}

		return tomlLoader.Parse()
	}

	log.Debug("attempting to load repo config from bare worktree, this may use an old config")
	ref, err := repo.Head()
	if err != nil {
		return Config{}, err
	}

	c, err := repo.CommitObject(ref.Hash())
	if err != nil {
		return Config{}, err
	}

	f, err := c.File(repoConfig)
	if err != nil {
		return Config{}, err
	}

	var tomlLoader TomlLoader
	r, err := f.Reader()
	if err != nil {
		return Config{}, err
	}
	_, err = toml.DecodeReader(r, &tomlLoader)
	if err != nil {
		return Config{}, err
	}

	return tomlLoader.Parse()
}
