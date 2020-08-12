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
	Regex       []*regexp.Regexp
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
	Description   string
	Regex         *regexp.Regexp
	FileNameRegex *regexp.Regexp
	FilePathRegex *regexp.Regexp
	Tags          []string
	Allowlist     Allowlist
	Entropies     []Entropy
}

// Config is a composite struct of Rules and Allowlists
// Each Rule contains a description, regular expression, tags, and allowlists if available
type Config struct {
	Rules     []Rule
	Allowlist Allowlist
}

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
	Allowlist TomlAllowList
	Rules     []struct {
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
		Allowlist []TomlAllowList
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
		var allowlist Allowlist
		for _, wl := range rule.Allowlist {
			var allowList Allowlist

			// rule specific regexes
			if len(wl.Regexes) != 0 {
				for _, regex := range wl.Regexes {
					wlRe, err := regexp.Compile(regex)
					if err != nil {
						return cfg, fmt.Errorf("problem loading config: %v", err)
					}
					allowList.Regex = append(allowList.Regex, wlRe)
				}
			}

			// rule specific filenames
			if len(wl.Regexes) != 0 {
				for _, regex := range wl.Regexes {
					wlRe, err := regexp.Compile(regex)
					if err != nil {
						return cfg, fmt.Errorf("problem loading config: %v", err)
					}
					allowList.Regex = append(allowList.Regex, wlRe)
				}
			}

			// rule specifc filepaths
			if len(wl.Paths) != 0 {
				for _, p := range wl.Paths {
					wlRe, err := regexp.Compile(p)
					if err != nil {
						return cfg, fmt.Errorf("problem loading config: %v", err)
					}
					allowList.Paths = append(allowList.Paths, wlRe)
				}
			}

			// rule specifc filenames
			if len(wl.Files) != 0 {
				for _, f := range wl.Files {
					wlRe, err := regexp.Compile(f)
					if err != nil {
						return cfg, fmt.Errorf("problem loading config: %v", err)
					}
					allowList.Files = append(allowList.Files, wlRe)
				}
			}
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
			Allowlist:     allowlist,
			Entropies:     entropies,
		}

		cfg.Rules = append(cfg.Rules, r)
	}

	// global regex allowLists
	for _, allowListRegex := range tomlLoader.Allowlist.Regexes {
		re, err := regexp.Compile(allowListRegex)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Regex = append(cfg.Allowlist.Regex, re)
	}

	// global file name allowLists
	for _, allowListFileName := range tomlLoader.Allowlist.Files {
		re, err := regexp.Compile(allowListFileName)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Files = append(cfg.Allowlist.Files, re)
	}

	// global file path allowLists
	for _, allowListFilePath := range tomlLoader.Allowlist.Paths {
		re, err := regexp.Compile(allowListFilePath)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Paths = append(cfg.Allowlist.Paths, re)
	}

	// global repo allowLists
	for _, allowListRepo := range tomlLoader.Allowlist.Repos {
		re, err := regexp.Compile(allowListRepo)
		if err != nil {
			return cfg, fmt.Errorf("problem loading config: %v", err)
		}
		cfg.Allowlist.Repos = append(cfg.Allowlist.Repos, re)
	}

	cfg.Allowlist.Commits = tomlLoader.Allowlist.Commits
	cfg.Allowlist.Description = tomlLoader.Allowlist.Description

	return cfg, nil
}
