package config

import (
	_ "embed"
	"fmt"
	"math"
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

type Rule struct {
	Description    string
	RuleID         string
	Entropy        float64
	EntropyReGroup int
	Regex          *regexp.Regexp
	Path           *regexp.Regexp
	Tags           []string
	Allowlist      Allowlist
}

func (vc *ViperConfig) Translate() (Config, error) {
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

		r := &Rule{
			Description:    r.Description,
			RuleID:         r.ID,
			Regex:          regexp.MustCompile(r.Regex),
			Path:           regexp.MustCompile(r.Path),
			EntropyReGroup: r.EntropyGroup,
			Entropy:        r.Entropy,
			Tags:           r.Tags,
			Allowlist: Allowlist{
				Regexes: alr,
				Paths:   alp,
				Commits: r.Allowlist.Commits,
			},
		}
		if r.EntropyReGroup > r.Regex.NumSubexp() {
			return Config{}, fmt.Errorf("%s invalid regex entropy group %d, max regex entropy group %d", r.Description, r.EntropyReGroup, r.Regex.NumSubexp())
		}
		rules = append(rules, r)

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
	}, nil
}

func (r *Rule) EntropySet() bool {
	if r.Entropy == 0.0 {
		return false
	}
	return true
}

func (r *Rule) IncludeEntropy(secret string) (bool, float64) {
	groups := r.Regex.FindStringSubmatch(secret)
	if len(groups)-1 > r.EntropyReGroup {
		// Config validation should prevent this
		return false, 0.0
	}
	// group = 0 will check the entropy of the whole regex match
	e := ShannonEntropy(groups[r.EntropyReGroup])
	if e > r.Entropy {
		return true, e
	}

	return false, 0.0
}

// shannonEntropy calculates the entropy of data using the formula defined here:
// https://en.wiktionary.org/wiki/Shannon_entropy
// Another way to think about what this is doing is calculating the number of bits
// needed to on average encode the data. So, the higher the entropy, the more random the data, the
// more bits needed to encode that data.
func ShannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}
