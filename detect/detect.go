package detect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/fatih/semgroup"

	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

const (
	gitleaksAllowSignature = "gitleaks:allow"
	chunkSize              = 10 * 1_000 // 10kb
)

// Detector is the main detector struct
type Detector struct {
	// Config is the configuration for the detector
	Config config.Config

	// Redact is a flag to redact findings. This is exported
	// so users using gitleaks as a library can set this flag
	// without calling `detector.Start(cmd *cobra.Command)`
	Redact uint

	// verbose is a flag to print findings
	Verbose bool

	// files larger than this will be skipped
	MaxTargetMegaBytes int

	// followSymlinks is a flag to enable scanning symlink files
	FollowSymlinks bool

	// NoColor is a flag to disable color output
	NoColor bool

	// IgnoreGitleaksAllow is a flag to ignore gitleaks:allow comments.
	IgnoreGitleaksAllow bool

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	commitMap map[string]bool

	// findingMutex is to prevent concurrent access to the
	// findings slice when adding findings.
	findingMutex *sync.Mutex

	// findings is a slice of report.Findings. This is the result
	// of the detector's scan which can then be used to generate a
	// report.
	findings []report.Finding

	// prefilter is a ahocorasick struct used for doing efficient string
	// matching given a set of words (keywords from the rules in the config)
	prefilter ahocorasick.Trie

	// a list of known findings that should be ignored
	baseline []report.Finding

	// path to baseline
	baselinePath string

	// gitleaksIgnore
	gitleaksIgnore map[string]bool

	// Sema (https://github.com/fatih/semgroup) controls the concurrency
	Sema *semgroup.Group
}

// Fragment contains the data to be scanned
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// FilePath is the path to the file if applicable
	FilePath    string
	SymlinkFile string

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string

	// newlineIndices is a list of indices of newlines in the raw content.
	// This is used to calculate the line location of a finding
	newlineIndices [][]int

	// keywords is a map of all the keywords contain within the contents
	// of this fragment
	keywords map[string]bool
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg config.Config) *Detector {
	return &Detector{
		commitMap:      make(map[string]bool),
		gitleaksIgnore: make(map[string]bool),
		findingMutex:   &sync.Mutex{},
		findings:       make([]report.Finding, 0),
		Config:         cfg,
		prefilter:      *ahocorasick.NewTrieBuilder().AddStrings(cfg.Keywords).Build(),
		Sema:           semgroup.NewGroup(context.Background(), 40),
	}
}

// NewDetectorDefaultConfig creates a new detector with the default config
func NewDetectorDefaultConfig() (*Detector, error) {
	viper.SetConfigType("toml")
	err := viper.ReadConfig(strings.NewReader(config.DefaultConfig))
	if err != nil {
		return nil, err
	}
	var vc config.ViperConfig
	err = viper.Unmarshal(&vc)
	if err != nil {
		return nil, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}
	return NewDetector(cfg), nil
}

func (d *Detector) AddGitleaksIgnore(gitleaksIgnorePath string) error {
	log.Debug().Msgf("found .gitleaksignore file: %s", gitleaksIgnorePath)
	file, err := os.Open(gitleaksIgnorePath)

	if err != nil {
		return err
	}

	// https://github.com/securego/gosec/issues/512
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn().Msgf("Error closing .gitleaksignore file: %s\n", err)
		}
	}()
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		d.gitleaksIgnore[scanner.Text()] = true
	}
	return nil
}

// DetectBytes scans the given bytes and returns a list of findings
func (d *Detector) DetectBytes(content []byte) []report.Finding {
	return d.DetectString(string(content))
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []report.Finding {
	return d.Detect(Fragment{
		Raw: content,
	})
}

// Detect scans the given fragment and returns a list of findings
func (d *Detector) Detect(fragment Fragment) []report.Finding {
	var findings []report.Finding

	// initiate fragment keywords
	fragment.keywords = make(map[string]bool)

	// check if filepath is allowed
	if fragment.FilePath != "" && (d.Config.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.Config.Path || (d.baselinePath != "" && fragment.FilePath == d.baselinePath)) {
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = regexp.MustCompile("\n").FindAllStringIndex(fragment.Raw, -1)

	// build keyword map for prefiltering rules
	normalizedRaw := strings.ToLower(fragment.Raw)
	matches := d.prefilter.MatchString(normalizedRaw)
	for _, m := range matches {
		fragment.keywords[normalizedRaw[m.Pos():int(m.Pos())+len(m.Match())]] = true
	}

	for _, rule := range d.Config.Rules {
		if len(rule.Keywords) == 0 {
			// if not keywords are associated with the rule always scan the
			// fragment using the rule
			findings = append(findings, d.detectRule(fragment, rule)...)
			continue
		}
		fragmentContainsKeyword := false
		// check if keywords are in the fragment
		for _, k := range rule.Keywords {
			if _, ok := fragment.keywords[strings.ToLower(k)]; ok {
				fragmentContainsKeyword = true
			}
		}
		if fragmentContainsKeyword {
			findings = append(findings, d.detectRule(fragment, rule)...)
		}
	}
	return filter(findings, d.Redact)
}

// detectRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectRule(fragment Fragment, rule config.Rule) []report.Finding {
	var findings []report.Finding

	// check if filepath or commit is allowed for this rule
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return findings
	}

	if rule.Path != nil && rule.Regex == nil {
		// Path _only_ rule
		if rule.Path.MatchString(fragment.FilePath) {
			finding := report.Finding{
				Description: rule.Description,
				File:        fragment.FilePath,
				SymlinkFile: fragment.SymlinkFile,
				RuleID:      rule.RuleID,
				Match:       fmt.Sprintf("file detected: %s", fragment.FilePath),
				Tags:        rule.Tags,
			}
			return append(findings, finding)
		}
	} else if rule.Path != nil {
		// if path is set _and_ a regex is set, then we need to check both
		// so if the path does not match, then we should return early and not
		// consider the regex
		if !rule.Path.MatchString(fragment.FilePath) {
			return findings
		}
	}

	// if path only rule, skip content checks
	if rule.Regex == nil {
		return findings
	}

	// If flag configure and raw data size bigger then the flag
	if d.MaxTargetMegaBytes > 0 {
		rawLength := len(fragment.Raw) / 1000000
		if rawLength > d.MaxTargetMegaBytes {
			log.Debug().Msgf("skipping file: %s scan due to size: %d", fragment.FilePath, rawLength)
			return findings
		}
	}

	matchIndices := rule.Regex.FindAllStringIndex(fragment.Raw, -1)
	for _, matchIndex := range matchIndices {
		// extract secret from match
		secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], "\n")

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		loc := location(fragment, matchIndex)

		if matchIndex[1] > loc.endLineIndex {
			loc.endLineIndex = matchIndex[1]
		}

		finding := report.Finding{
			Description: rule.Description,
			File:        fragment.FilePath,
			SymlinkFile: fragment.SymlinkFile,
			RuleID:      rule.RuleID,
			StartLine:   loc.startLine,
			EndLine:     loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Secret:      secret,
			Match:       secret,
			Tags:        rule.Tags,
			Line:        fragment.Raw[loc.startLineIndex:loc.endLineIndex],
		}

		if strings.Contains(fragment.Raw[loc.startLineIndex:loc.endLineIndex],
			gitleaksAllowSignature) && !d.IgnoreGitleaksAllow {
			continue
		}

		// by default if secret group is not set, we will check to see if there
		// are any capture groups. If there are, we will use the first capture to start
		groups := rule.Regex.FindStringSubmatch(secret)
		if rule.SecretGroup == 0 {
			// if len(groups) == 2 that means there is only one capture group
			// the first element in groups is the full match, the second is the
			// first capture group
			if len(groups) == 2 {
				secret = groups[1]
				finding.Secret = secret
			}
		} else {
			if len(groups) <= rule.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				continue
			}
			secret = groups[rule.SecretGroup]
			finding.Secret = secret
		}

		// check if the regexTarget is defined in the allowlist "regexes" entry
		allowlistTarget := finding.Secret
		switch rule.Allowlist.RegexTarget {
		case "match":
			allowlistTarget = finding.Match
		case "line":
			allowlistTarget = finding.Line
		}

		globalAllowlistTarget := finding.Secret
		switch d.Config.Allowlist.RegexTarget {
		case "match":
			globalAllowlistTarget = finding.Match
		case "line":
			globalAllowlistTarget = finding.Line
		}
		if rule.Allowlist.RegexAllowed(allowlistTarget) ||
			d.Config.Allowlist.RegexAllowed(globalAllowlistTarget) {
			continue
		}

		// check if the secret is in the list of stopwords
		if rule.Allowlist.ContainsStopWord(finding.Secret) ||
			d.Config.Allowlist.ContainsStopWord(finding.Secret) {
			continue
		}

		// check entropy
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)
		if rule.Entropy != 0.0 {
			if entropy <= rule.Entropy {
				// entropy is too low, skip this finding
				continue
			}
			// NOTE: this is a goofy hack to get around the fact there golang's regex engine
			// does not support positive lookaheads. Ideally we would want to add a
			// restriction on generic rules regex that requires the secret match group
			// contains both numbers and alphabetical characters, not just alphabetical characters.
			// What this bit of code does is check if the ruleid is prepended with "generic" and enforces the
			// secret contains both digits and alphabetical characters.
			// TODO: this should be replaced with stop words
			if strings.HasPrefix(rule.RuleID, "generic") {
				if !containsDigit(secret) {
					continue
				}
			}
		}

		findings = append(findings, finding)
	}
	return findings
}

// addFinding synchronously adds a finding to the findings slice
func (d *Detector) addFinding(finding report.Finding) {
	globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	if finding.Commit != "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = globalFingerprint
	}

	// check if we should ignore this finding
	if _, ok := d.gitleaksIgnore[globalFingerprint]; ok {
		log.Debug().Msgf("ignoring finding with global Fingerprint %s",
			finding.Fingerprint)
		return
	} else if finding.Commit != "" {
		// Awkward nested if because I'm not sure how to chain these two conditions.
		if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
			log.Debug().Msgf("ignoring finding with Fingerprint %s",
				finding.Fingerprint)
			return
		}
	}

	if d.baseline != nil && !IsNew(finding, d.baseline) {
		log.Debug().Msgf("baseline duplicate -- ignoring finding with Fingerprint %s", finding.Fingerprint)
		return
	}

	d.findingMutex.Lock()
	d.findings = append(d.findings, finding)
	if d.Verbose {
		printFinding(finding, d.NoColor)
	}
	d.findingMutex.Unlock()
}

// addCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}
