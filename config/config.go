package config

import (
	_ "embed"
	"regexp"
)

//go:embed gitleaks.toml
var DefaultConfig string

type ViperConfig struct {
	Description string
	Rules       []struct {
		RuleID      string
		Description string
		Entropy     float32
		Regex       string
		Path        string
		ReportGroup int
		Tags        []string

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

// Config a a struct the viper library uses to unmarshal data into.
// This is a temporary structure that is an argument used in Translate.
type Config struct {
	Description string
	Rules       []*Rule
	Allowlist   Allowlist
}

type Rule struct {
	Description string
	RuleID      string
	Entropy     float32
	Regex       *regexp.Regexp
	Path        *regexp.Regexp
	ReportGroup int
	Tags        []string
	Allowlist   Allowlist
}

type Allowlist struct {
	Description string
	Regexes     []*regexp.Regexp
	Paths       []*regexp.Regexp
	Commits     []string
}

func (vc *ViperConfig) Translate() Config {
	var rules []*Rule
	for _, r := range vc.Rules {
		var alr []*regexp.Regexp
		for _, a := range r.Allowlist.Regexes {
			alr = append(alr, regexp.MustCompile(a))
		}
		var alp []*regexp.Regexp
		for _, a := range r.Allowlist.Paths {
			alp = append(alp, regexp.MustCompile(a))
		}

		rules = append(rules, &Rule{
			Description: r.Description,
			Entropy:     r.Entropy,
			Regex:       regexp.MustCompile(r.Regex),
			Path:        regexp.MustCompile(r.Path),
			ReportGroup: r.ReportGroup,
			Tags:        r.Tags,

			Allowlist: Allowlist{
				Regexes: alr,
				Paths:   alp,
				Commits: r.Allowlist.Commits,
			}})
	}
	var alr []*regexp.Regexp
	for _, a := range vc.Allowlist.Regexes {
		alr = append(alr, regexp.MustCompile(a))
	}
	var alp []*regexp.Regexp
	for _, a := range vc.Allowlist.Paths {
		alp = append(alp, regexp.MustCompile(a))
	}
	return Config{
		Description: vc.Description,
		Rules:       rules,
		Allowlist: Allowlist{
			Regexes: alr,
			Paths:   alp,
			Commits: vc.Allowlist.Commits,
		},
	}
}

func (c *Config) GloballyAllowedPath(path string) bool {
	return false
}
