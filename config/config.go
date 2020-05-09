package config

import (
	"fmt"
	"path"
	"regexp"
	"strconv"

	"github.com/zricethezav/gitleaks/v4/options"

	"github.com/BurntSushi/toml"
)

// Whitelist is struct containing items that if encountered will whitelist
// a commit/line of code that would be considered a leak.
type Whitelist struct {
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
// over during an audit. Each rule will be checked. If a regex match is found AND
// that match is not whitelisted (globally or locally), then a leak will be appended
// to the final audit report.
type Rule struct {
	Description   string
	Regex         *regexp.Regexp
	FileNameRegex *regexp.Regexp
	FilePathRegex *regexp.Regexp
	Tags          []string
	Whitelist     []Whitelist
	Entropies     []Entropy
}

// Config is a composite struct of Rules and Whitelists
// Each Rule contains a description, regular expression, tags, and whitelists if available
type Config struct {
	Rules     []Rule
	Whitelist struct {
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
	Whitelist struct {
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
		Whitelist []struct {
			Description string
			Regex       string
			File        string
			Path        string
		}
	}
}

// NewConfig will create a new config struct which contains
// rules on how gitleaks will proceed with its audit.
// If no options are passed via cli then NewConfig will return
// a default config which can be seen in config.go
func NewConfig(options options.Options) (Config, error) {
	var cfg Config
	tomlLoader := TomlLoader{}

	var err error
	if options.Config != "" {
		_, err = toml.DecodeFile(options.Config, &tomlLoader)
		// append a whitelist rule for whitelisting the config
		tomlLoader.Whitelist.Files = append(tomlLoader.Whitelist.Files, path.Base(options.Config))
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
// to create compiled regular expressions and rules used in audits
func (tomlLoader TomlLoader) Parse() (Config, error) {
	var cfg Config
	for _, rule := range tomlLoader.Rules {
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

		// rule specific whitelists
		var whitelists []Whitelist
		for _, wl := range rule.Whitelist {
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
			whitelists = append(whitelists, Whitelist{
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

		cfg.Rules = append(cfg.Rules, Rule{
			Description:   rule.Description,
			Regex:         re,
			FileNameRegex: fileNameRe,
			FilePathRegex: filePathRe,
			Tags:          rule.Tags,
			Whitelist:     whitelists,
			Entropies:     entropies,
		})
	}

	// global file name whitelists
	for _, wlFileName := range tomlLoader.Whitelist.Files {
		re, err := regexp.Compile(wlFileName)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Whitelist.Files = append(cfg.Whitelist.Files, re)
	}

	// global file path whitelists
	for _, wlFilePath := range tomlLoader.Whitelist.Paths {
		re, err := regexp.Compile(wlFilePath)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Whitelist.Paths = append(cfg.Whitelist.Paths, re)
	}

	// global repo whitelists
	for _, wlRepo := range tomlLoader.Whitelist.Repos {
		re, err := regexp.Compile(wlRepo)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Whitelist.Repos = append(cfg.Whitelist.Repos, re)
	}

	cfg.Whitelist.Commits = tomlLoader.Whitelist.Commits
	cfg.Whitelist.Description = tomlLoader.Whitelist.Description

	return cfg, nil
}
