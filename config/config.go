package config

import (
	_ "embed"
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
		ID          string
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

// Config is a configuration struct that contains rules and an allowlist if present.
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
			RuleID:      r.ID,
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
