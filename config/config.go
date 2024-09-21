package config

import (
	_ "embed"
	"fmt"
	"github.com/zricethezav/gitleaks/v8/config/flags"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/exp/maps"

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
		Report      *bool
		Verify      Verify

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
	Extend      Extend
	Path        string
	Description string
	Rules       map[string]Rule
	Allowlist   Allowlist
	Keywords    []string

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
		keywords     []string
		orderedRules []string

		rulesMap         = make(map[string]Rule)
		ruleDependencies = make(map[string]map[string]struct{})
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
				keywords = append(keywords, strings.ToLower(k))
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
		rule := Rule{
			Description: r.Description,
			RuleID:      r.ID,
			Regex:       configRegex,
			Path:        configPathRegex,
			SecretGroup: r.SecretGroup,
			Entropy:     r.Entropy,
			Tags:        r.Tags,
			Keywords:    r.Keywords,
			Verify: Verify{
				HTTPVerb:             r.Verify.HTTPVerb,
				URL:                  r.Verify.URL,
				Headers:              r.Verify.Headers,
				ExpectedStatus:       r.Verify.ExpectedStatus,
				ExpectedBodyContains: r.Verify.ExpectedBodyContains,
			},
			Allowlist: Allowlist{
				RegexTarget: r.Allowlist.RegexTarget,
				Regexes:     allowlistRegexes,
				Paths:       allowlistPaths,
				Commits:     r.Allowlist.Commits,
				StopWords:   r.Allowlist.StopWords,
			},
		}
		if r.Report == nil || *r.Report {
			rule.Report = true
		}

		if flags.EnableExperimentalVerification.Load() && r.Verify.URL != "" {
			if err := r.Verify.Validate(rule.RuleID); err != nil {
				return Config{}, err
			}
			rule.Verify = r.Verify
			if len(rule.Verify.GetRequiredIDs()) > 0 {
				for requiredID := range rule.Verify.GetRequiredIDs() {
					if _, ok := ruleDependencies[requiredID]; !ok {
						ruleDependencies[requiredID] = make(map[string]struct{})
					}
					ruleDependencies[requiredID][rule.RuleID] = struct{}{}
				}
			}
		}
		orderedRules = append(orderedRules, rule.RuleID)
		rulesMap[rule.RuleID] = rule

		if err := rule.Validate(); err != nil {
			return Config{}, err
		}
	}

	// Validate IDs in |verify.requires|.
	for ruleID, dependentIDs := range ruleDependencies {
		if _, ok := rulesMap[ruleID]; !ok {
			return Config{}, fmt.Errorf("rule ID '%s' required by '%v' does not exist", ruleID, maps.Keys(dependentIDs))
		}
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
	for ruleID, rule := range extensionConfig.Rules {
		if _, ok := c.Rules[ruleID]; !ok {
			log.Trace().Msgf("adding %s to base config", ruleID)
			c.Rules[ruleID] = rule
			c.Keywords = append(c.Keywords, rule.Keywords...)
			c.OrderedRules = append(c.OrderedRules, ruleID)
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

// TODO: Deduplicate these patterns between here and verify.go
var (
	verifyHelperFuncPat = regexp.MustCompile(`\${([A-Za-z0-9]{3,15})\("(.+?)"\)}`)
	helperFuncs         = map[string]struct{}{
		"base64":    {},
		"urlEncode": {},
	}
	verifyPlaceholderPat = regexp.MustCompile(`(?i)\${([a-z0-9\-]*)}`)
)

func checkVerifyHelperFuncs(s string) error {
	for _, match := range verifyHelperFuncPat.FindAllStringSubmatch(s, -1) {
		if _, ok := helperFuncs[match[1]]; !ok {
			return fmt.Errorf("unknown helper function '%s' (known: %v)", match[1], maps.Keys(helperFuncs))
		}
	}
	return nil
}
