package config

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/viper"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
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
		Regex       string
		SecretGroup int
		Entropy     float64
		Keywords    []string
		Path        string
		Tags        []string

		// Deprecated: this is a shim for backwards-compatibility. It should be removed in 9.x.
		AllowList  *viperRuleAllowlist
		Allowlists []viperRuleAllowlist
	}
	Allowlist struct {
		Commits     []string
		Paths       []string
		RegexTarget string
		Regexes     []string
		StopWords   []string
	}
}

type viperRuleAllowlist struct {
	Description string
	Condition   string
	Commits     []string
	Paths       []string
	RegexTarget string
	Regexes     []string
	StopWords   []string
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
	Path          string
	URL           string
	UseDefault    bool
	DisabledRules []string
}

func (vc *ViperConfig) Translate() (Config, error) {
	var (
		keywords     = make(map[string]struct{})
		orderedRules []string
		rulesMap     = make(map[string]Rule)
	)

	// Validate individual rules.
	for _, vr := range vc.Rules {
		if vr.Keywords == nil {
			vr.Keywords = []string{}
		} else {
			for i, k := range vr.Keywords {
				keyword := strings.ToLower(k)
				keywords[keyword] = struct{}{}
				vr.Keywords[i] = keyword
			}
		}

		if vr.Tags == nil {
			vr.Tags = []string{}
		}

		var configRegex *regexp.Regexp
		var configPathRegex *regexp.Regexp
		if vr.Regex != "" {
			configRegex = regexp.MustCompile(vr.Regex)
		}
		if vr.Path != "" {
			configPathRegex = regexp.MustCompile(vr.Path)
		}

		cr := Rule{
			RuleID:      vr.ID,
			Description: vr.Description,
			Regex:       configRegex,
			SecretGroup: vr.SecretGroup,
			Entropy:     vr.Entropy,
			Path:        configPathRegex,
			Keywords:    vr.Keywords,
			Tags:        vr.Tags,
		}
		// Parse the allowlist, including the older format for backwards compatibility.
		if vr.AllowList != nil {
			if len(vr.Allowlists) > 0 {
				return Config{}, fmt.Errorf("%s: [rules.allowlist] is deprecated, it cannot be used alongside [[rules.allowlist]]", cr.RuleID)
			}
			vr.Allowlists = append(vr.Allowlists, *vr.AllowList)
		}
		for _, a := range vr.Allowlists {
			var condition AllowlistMatchCondition
			c := strings.ToUpper(a.Condition)
			switch c {
			case "AND", "&&":
				condition = AllowlistMatchAnd
			case "", "OR", "||":
				condition = AllowlistMatchOr
			default:
				return Config{}, fmt.Errorf("%s: unknown allowlist condition '%s' (expected 'and', 'or')", cr.RuleID, c)
			}

			// Validate the target.
			if a.RegexTarget != "" {
				switch a.RegexTarget {
				case "secret":
					a.RegexTarget = ""
				case "match", "line":
					// do nothing
				default:
					return Config{}, fmt.Errorf("%s: unknown allowlist |regexTarget| '%s' (expected 'match', 'line')", cr.RuleID, a.RegexTarget)
				}
			}
			var allowlistRegexes []*regexp.Regexp
			for _, a := range a.Regexes {
				allowlistRegexes = append(allowlistRegexes, regexp.MustCompile(a))
			}
			var allowlistPaths []*regexp.Regexp
			for _, a := range a.Paths {
				allowlistPaths = append(allowlistPaths, regexp.MustCompile(a))
			}

			allowlist := Allowlist{
				MatchCondition: condition,
				RegexTarget:    a.RegexTarget,
				Regexes:        allowlistRegexes,
				Paths:          allowlistPaths,
				Commits:        a.Commits,
				StopWords:      a.StopWords,
			}
			if err := allowlist.Validate(); err != nil {
				return Config{}, fmt.Errorf("%s: %w", cr.RuleID, err)
			}
			cr.Allowlists = append(cr.Allowlists, allowlist)
		}
		orderedRules = append(orderedRules, cr.RuleID)
		rulesMap[cr.RuleID] = cr
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
			logging.Fatal().Msg("unable to load config due to extend.path and extend.useDefault being set")
		}
		if c.Extend.UseDefault {
			c.extendDefault()
		} else if c.Extend.Path != "" {
			c.extendPath()
		}
	}

	// Validate the rules after everything has been assembled (including extended configs).
	if extendDepth == 0 {
		for _, rule := range c.Rules {
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
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	defaultViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&defaultViperConfig); err != nil {
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := defaultViperConfig.Translate()
	if err != nil {
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	logging.Debug().Msg("extending config with default config")
	c.extend(cfg)

}

func (c *Config) extendPath() {
	extendDepth++
	viper.SetConfigFile(c.Extend.Path)
	if err := viper.ReadInConfig(); err != nil {
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	extensionViperConfig := ViperConfig{}
	if err := viper.Unmarshal(&extensionViperConfig); err != nil {
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	cfg, err := extensionViperConfig.Translate()
	if err != nil {
		logging.Fatal().Msgf("failed to load extended config, err: %s", err)
		return
	}
	logging.Debug().Msgf("extending config with %s", c.Extend.Path)
	c.extend(cfg)
}

func (c *Config) extendURL() {
	// TODO
}

func (c *Config) extend(extensionConfig Config) {
	// Get config name for helpful log messages.
	var configName string
	if c.Extend.Path != "" {
		configName = c.Extend.Path
	} else {
		configName = "default"
	}
	// Convert |Config.DisabledRules| into a map for ease of access.
	disabledRuleIDs := map[string]struct{}{}
	for _, id := range c.Extend.DisabledRules {
		if _, ok := extensionConfig.Rules[id]; !ok {
			logging.Warn().
				Str("rule-id", id).
				Str("config", configName).
				Msg("Disabled rule doesn't exist in extended config.")
		}
		disabledRuleIDs[id] = struct{}{}
	}

	for ruleID, baseRule := range extensionConfig.Rules {
		// Skip the rule.
		if _, ok := disabledRuleIDs[ruleID]; ok {
			logging.Debug().
				Str("rule-id", ruleID).
				Str("config", configName).
				Msg("Ignoring rule from extended config.")
			continue
		}

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
			baseRule.Tags = append(baseRule.Tags, currentRule.Tags...)
			baseRule.Keywords = append(baseRule.Keywords, currentRule.Keywords...)
			for _, a := range currentRule.Allowlists {
				baseRule.Allowlists = append(baseRule.Allowlists, a)
			}
			// The keywords from the base rule and the extended rule must be merged into the global keywords list
			for _, k := range baseRule.Keywords {
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
