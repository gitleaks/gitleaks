package config

import (
	_ "embed"
	"regexp"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

//go:embed gitleaks.toml
var DefaultConfig string

// use to keep track of how many configs we can extend
// yea I know, globals bad
var extendDepth int

const maxExtendDepth = 2

// ViperConfig is the config struct used by the Viper config package
// to parse the config file. This struct does not include regular expressions.
// It is used as an intermediary to convert the Viper config to the Config struct.
type ViperConfig struct {
	Description string
	Extend      Extend
	Rules       []struct {
		ID          string
		Description string
		Entropy     float64
		SecretGroup int
		Regex       string
		Keywords    []string
		Path        string
		Tags        []string

		Allowlist struct {
			RegexTarget string
			Regexes     []string
			Paths       []string
			Commits     []string
			StopWords   []string
		}
	}
	Allowlist struct {
		RegexTarget string
		Regexes     []string
		Paths       []string
		Commits     []string
		StopWords   []string
	}
}

// Config is a configuration struct that contains rules and an allowlist if present.
type Config struct {
	Title       string
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Allowlist   Allowlist
	Keywords    map[string]struct{}

	// used to keep sarif results consistent
	OrderedRules []string
}

// Extend is a struct that allows users to define how they want their
// configuration extended by other configuration files.
type Extend struct {
	Path       string
	URL        string
	UseDefault bool
}

func (vc *ViperConfig) Translate() (Config, error) {
	var (
		keywords     = make(map[string]struct{})
		orderedRules []string
		rulesMap     = make(map[string]Rule)
	)

	for _, r := range vc.Rules {
		var allowlistRegexes []*regexp.Regexp
		for _, a := range r.Allowlist.Regexes {
			allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
		}
		var allowlistPaths []*regexp.Regexp
		for _, a := range r.Allowlist.Paths {
			allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
		}

		if r.Keywords == nil {
			r.Keywords = []string{}
		} else {
			for _, k := range r.Keywords {
				keywords[strings.ToLower(k)] = struct{}{}
			}
		}

		if r.Tags == nil {
			r.Tags = []string{}
		}

		var configRegex *regexp.Regexp
		var configPathRegex *regexp.Regexp
		if r.Regex == "" {
			configRegex = nil
		} else {
			configRegex = regexp.MustCompile(r.Regex)
		}
		if r.Path == "" {
			configPathRegex = nil
		} else {
			configPathRegex = regexp.MustCompile(r.Path)
		}
		r := Rule{
			RuleID:      r.ID,
			Description: r.Description,
			Regex:       configRegex,
			Path:        configPathRegex,
			SecretGroup: r.SecretGroup,
			Entropy:     r.Entropy,
			Tags:        r.Tags,
			Keywords:    r.Keywords,
			Allowlist: Allowlist{
				RegexTarget: r.Allowlist.RegexTarget,
				Regexes:     allowlistRegexes,
				Paths:       allowlistPaths,
				Commits:     r.Allowlist.Commits,
				StopWords:   r.Allowlist.StopWords,
			},
		}

		orderedRules = append(orderedRules, r.RuleID)
		rulesMap[r.RuleID] = r
	}
	var allowlistRegexes []*regexp.Regexp
	for _, a := range vc.Allowlist.Regexes {
		allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
	}
	var allowlistPaths []*regexp.Regexp
	for _, a := range vc.Allowlist.Paths {
		allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
	}
	c := Config{
		Description: vc.Description,
		Extend:      vc.Extend,
		Rules:       rulesMap,
		Allowlist: Allowlist{
			RegexTarget: vc.Allowlist.RegexTarget,
			Regexes:     allowlistRegexes,
			Paths:       allowlistPaths,
			Commits:     vc.Allowlist.Commits,
			StopWords:   vc.Allowlist.StopWords,
		},
		Keywords:     keywords,
		OrderedRules: orderedRules,
	}

	if maxExtendDepth != extendDepth {
		// disallow both usedefault and path from being set
		if c.Extend.Path != "" && c.Extend.UseDefault {
			log.Fatal().Msg("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			c.extendDefault()
		} else if c.Extend.Path != "" {
			c.extendPath()
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if extendDepth == 0 {
		for _, rule := range rulesMap {
			if err := rule.Validate(); err != nil {
				return Config{}, err
			}
		}
	}

	return c, nil
}

func (c *Config) GetOrderedRules() []Rule {
	var orderedRules []Rule
	for _, id := range c.OrderedRules {
		if _, ok := c.Rules[id]; ok {
			orderedRules = append(orderedRules, c.Rules[id])
		}
	}
	return orderedRules
}

func (c *Config) extendDefault() {
	extendDepth++
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(DefaultConfig)); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	defaultViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&defaultViperConfig); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := defaultViperConfig.Translate()
	if err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	log.Debug().Msg("extending config with default config")
	c.extend(cfg)

}

func (c *Config) extendPath() {
	extendDepth++
	viper.SetConfigFile(c.Extend.Path)
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	extensionViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&extensionViperConfig); err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := extensionViperConfig.Translate()
	if err != nil {
		log.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	log.Debug().Msgf("extending config with %s", c.Extend.Path)
	c.extend(cfg)
}

func (c *Config) extendURL() {
	// TODO
}

func (c *Config) extend(extensionConfig Config) {
	for ruleID, baseRule := range extensionConfig.Rules {
		currentRule, ok := c.Rules[ruleID]
		if !ok {
			// Rule doesn't exist, add it to the config.
			c.Rules[ruleID] = baseRule
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			c.OrderedRules = append(c.OrderedRules, ruleID)
		} else {
			// Rule exists, merge our changes into the base.
			if currentRule.Description != "" {
				baseRule.Description = currentRule.Description
			}
			if currentRule.Entropy != 0 {
				baseRule.Entropy = currentRule.Entropy
			}
			if currentRule.SecretGroup != 0 {
				baseRule.SecretGroup = currentRule.SecretGroup
			}
			if currentRule.Regex != nil {
				baseRule.Regex = currentRule.Regex
			}
			if currentRule.Path != nil {
				baseRule.Path = currentRule.Path
			}
			if len(currentRule.Tags) > 0 {
				baseRule.Tags = currentRule.Tags
			}
			if len(currentRule.Keywords) > 0 {
				baseRule.Keywords = currentRule.Keywords
			}
			baseRule.Allowlist.Commits = append(baseRule.Allowlist.Commits, currentRule.Allowlist.Commits...)
			baseRule.Allowlist.Paths = append(baseRule.Allowlist.Paths, currentRule.Allowlist.Paths...)
			baseRule.Allowlist.Regexes = append(baseRule.Allowlist.Regexes, currentRule.Allowlist.Regexes...)
			baseRule.Allowlist.RegexTarget = currentRule.Allowlist.RegexTarget
			baseRule.Allowlist.StopWords = append(baseRule.Allowlist.StopWords, currentRule.Allowlist.StopWords...)
			// The keywords from the base rule and the extended rule must be merged into the global keywords list
			for _, k := range baseRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			for _, k := range currentRule.Keywords {
				c.Keywords[k] = struct{}{}
			}
			c.Rules[ruleID] = baseRule
		}
	}

	// append allowlists, not attempting to merge
	c.Allowlist.Commits = append(c.Allowlist.Commits,
		extensionConfig.Allowlist.Commits...)
	c.Allowlist.Paths = append(c.Allowlist.Paths,
		extensionConfig.Allowlist.Paths...)
	c.Allowlist.Regexes = append(c.Allowlist.Regexes,
		extensionConfig.Allowlist.Regexes...)

	// sort to keep extended rules in order
	sort.Strings(c.OrderedRules)
}
