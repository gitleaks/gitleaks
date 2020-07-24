package config

import (
	"fmt"
	"path"
	"regexp"
	"strconv"

	"github.com/zricethezav/gitleaks/v5/options"

	"github.com/BurntSushi/toml"
	log "github.com/sirupsen/logrus"
)

// Allowlist is struct containing items that if encountered will allowlist
// a commit/line of code that would be considered a leak.
type Allowlist struct {
	Description string
	Regex       *regexp.Regexp
	File        *regexp.Regexp
	Path        *regexp.Regexp
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
	Description   string
	Regex         *regexp.Regexp
	FileNameRegex *regexp.Regexp
	FilePathRegex *regexp.Regexp
	Tags          []string
	Allowlist     []Allowlist
	Entropies     []Entropy
}

// Config is a composite struct of Rules and Allowlists
// Each Rule contains a description, regular expression, tags, and allowlists if available
type Config struct {
	Rules     []Rule
	Allowlist struct {
		Description string
		Commits     []string
		Files       []*regexp.Regexp
		Paths       []*regexp.Regexp
		Repos       []*regexp.Regexp
	}
}

// TomlLoader gets loaded with the values from a gitleaks toml config
// see the config in config/defaults.go for an example. TomlLoader is used
// to generate Config values (compiling regexes, etc).
type TomlLoader struct {
	Allowlist struct {
		Description string
		Commits     []string
		Files       []string
		Paths       []string
		Repos       []string
	}
	Rules []struct {
		Description   string
		Regex         string
		FileNameRegex string
		FilePathRegex string
		Tags          []string
		Entropies     []struct {
			Min   string
			Max   string
			Group string
		}
		Allowlist []struct {
			Description string
			Regex       string
			File        string
			Path        string
		}
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
	if options.Config != "" {
		_, err = toml.DecodeFile(options.Config, &tomlLoader)
		// append a allowlist rule for allowlisting the config
		tomlLoader.Allowlist.Files = append(tomlLoader.Allowlist.Files, path.Base(options.Config))
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
		if rule.Regex == "" && rule.FilePathRegex == "" && rule.FileNameRegex == "" && len(rule.Entropies) == 0 {
			log.Warnf("Rule %s does not define any actionable data", rule.Description)
			continue
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		fileNameRe, err := regexp.Compile(rule.FileNameRegex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		filePathRe, err := regexp.Compile(rule.FilePathRegex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}

		// rule specific allowlists
		var allowlists []Allowlist
		for _, wl := range rule.Allowlist {
			wlRe, err := regexp.Compile(wl.Regex)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			wlFileNameRe, err := regexp.Compile(wl.File)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			wlFilePathRe, err := regexp.Compile(wl.Path)
			if err != nil {
				return cfg, fmt.Errorf("problem loading config: %v", err)
			}
			allowlists = append(allowlists, Allowlist{
				Description: wl.Description,
				File:        wlFileNameRe,
				Path:        wlFilePathRe,
				Regex:       wlRe,
			})
		}

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
			Description:   rule.Description,
			Regex:         re,
			FileNameRegex: fileNameRe,
			FilePathRegex: filePathRe,
			Tags:          rule.Tags,
			Allowlist:     allowlists,
			Entropies:     entropies,
		}

		cfg.Rules = append(cfg.Rules, r)
	}

	// global file name allowlists
	for _, wlFileName := range tomlLoader.Allowlist.Files {
		re, err := regexp.Compile(wlFileName)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Files = append(cfg.Allowlist.Files, re)
	}

	// global file path allowlists
	for _, wlFilePath := range tomlLoader.Allowlist.Paths {
		re, err := regexp.Compile(wlFilePath)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Paths = append(cfg.Allowlist.Paths, re)
	}

	// global repo allowlists
	for _, wlRepo := range tomlLoader.Allowlist.Repos {
		re, err := regexp.Compile(wlRepo)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Repos = append(cfg.Allowlist.Repos, re)
	}

	cfg.Allowlist.Commits = tomlLoader.Allowlist.Commits
	cfg.Allowlist.Description = tomlLoader.Allowlist.Description

	return cfg, nil
}
