package config

import (
	_ "embed"
	"fmt"
	"regexp"
)

//go:embed gitleaks.toml
var DefaultConfig string

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
type ViperConfig struct {
	Description string
	Rules       []struct {
		ID           string
		Description  string
		Entropy      float64
		EntropyGroup int
		Regex        string
		Path         string
		Tags         []string

		Allowlist struct {
			Regexes []string
			Paths   []string
			Commits []string
		}
	}
	Allowlist struct {
		Regexes []string
		Paths   []string
		Commits []string
	}
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Description string
	Rules       []*Rule
	Allowlist   Allowlist
}

func (vc *ViperConfig) Translate() (Config, error) {
	var rules []*Rule
	for _, r := range vc.Rules {
		var allowlistRegexes []*regexp.Regexp
		for _, a := range r.Allowlist.Regexes {
			allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
		}
		var allowlistPaths []*regexp.Regexp
		for _, a := range r.Allowlist.Paths {
			allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
		}

		r := &Rule{
			Description:    r.Description,
			RuleID:         r.ID,
			Regex:          regexp.MustCompile(r.Regex),
			Path:           regexp.MustCompile(r.Path),
			EntropyReGroup: r.EntropyGroup,
			Entropy:        r.Entropy,
			Tags:           r.Tags,
			Allowlist: Allowlist{
				Regexes: allowlistRegexes,
				Paths:   allowlistPaths,
				Commits: r.Allowlist.Commits,
			},
		}
		if r.EntropyReGroup > r.Regex.NumSubexp() {
			return Config{}, fmt.Errorf("%s invalid regex entropy group %d, max regex entropy group %d", r.Description, r.EntropyReGroup, r.Regex.NumSubexp())
		}
		rules = append(rules, r)

	}
	var allowlistRegexes []*regexp.Regexp
	for _, a := range vc.Allowlist.Regexes {
		allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
	}
	var allowlistPaths []*regexp.Regexp
	for _, a := range vc.Allowlist.Paths {
		allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
	}
	return Config{
		Description: vc.Description,
		Rules:       rules,
		Allowlist: Allowlist{
			Regexes: allowlistRegexes,
			Paths:   allowlistPaths,
			Commits: vc.Allowlist.Commits,
		},
	}, nil
}
