package config

import (
	_ "embed"
	"regexp"
)

//go:embed gitleaks.toml
var DefaultConfig string

// Config a a struct the viper library uses to unmarshal data into.
// This is a temporary structure that is an argument used in Translate.
type Config struct {
	Description string
	Rules       []*Rule
	Allowlist   Allowlist
}

type Rule struct {
	Description   string
	Entropy       float32
	Regex         string
	RegexCompiled *regexp.Regexp
	Path          string
	PathCompiled  *regexp.Regexp
	ReportGroup   int
	Tags          []string
	Allowlist     Allowlist
}

type Allowlist struct {
	Description     string
	Regexes         []string
	RegexesCompiled []*regexp.Regexp
	Paths           []string
	PathsCompiled   []*regexp.Regexp
	Commits         []string
}

func (c *Config) Compile() {
	for _, r := range c.Rules {
		r.compile()
	}
	c.Allowlist.compile()
}

func (r *Rule) compile() {
	r.RegexCompiled = regexp.MustCompile(r.Regex)
	r.PathCompiled = regexp.MustCompile(r.Path)
	r.Allowlist.compile()
}

func (a *Allowlist) compile() {
	var (
		regexes []*regexp.Regexp
		paths   []*regexp.Regexp
	)
	for _, r := range a.Regexes {
		regexes = append(regexes, regexp.MustCompile(r))
	}
	for _, p := range a.Paths {
		paths = append(paths, regexp.MustCompile(p))
	}
	a.PathsCompiled = paths
	a.RegexesCompiled = regexes
}

func (c *Config) GloballyAllowedPath(path string) bool {
	return false
}
