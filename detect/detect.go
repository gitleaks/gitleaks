package detect

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/codec"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
	"github.com/zricethezav/gitleaks/v8/report"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/fatih/semgroup"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
)

const (
	gitleaksAllowSignature = "gitleaks:allow"
	chunkSize              = 100 * 1_000 // 100kb

	// SlowWarningThreshold is the amount of time to wait before logging that a file is slow.
	// This is useful for identifying problematic files and tuning the allowlist.
	SlowWarningThreshold = 5 * time.Second
)

var (
	newLineRegexp = regexp.MustCompile("\n")
	isWindows     = runtime.GOOS == "windows"
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

	// MaxDecodeDepths limits how many recursive decoding passes are allowed
	MaxDecodeDepth int

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
	gitleaksIgnore     map[string]struct{}
	gitleaksGlobIgnore []globIgnoreEntry

	// Sema (https://github.com/fatih/semgroup) controls the concurrency
	Sema *semgroup.Group

	// report-related settings.
	ReportPath string
	Reporter   report.Reporter

	TotalBytes atomic.Uint64
}

// Fragment contains the data to be scanned
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// FilePath is the path to the file, if applicable.
	// The path separator MUST be normalized to `/`.
	FilePath    string
	SymlinkFile string
	// WindowsFilePath is the path with the original separator.
	// This provides a backwards-compatible solution to https://github.com/gitleaks/gitleaks/issues/1565.
	WindowsFilePath string `json:"-"` // TODO: remove this in v9.

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string

	// newlineIndices is a list of indices of newlines in the raw content.
	// This is used to calculate the line location of a finding
	newlineIndices [][]int
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg config.Config) *Detector {
	return &Detector{
		commitMap:          make(map[string]bool),
		gitleaksIgnore:     make(map[string]struct{}),
		gitleaksGlobIgnore: make([]globIgnoreEntry, 0),
		findingMutex:       &sync.Mutex{},
		findings:           make([]report.Finding, 0),
		Config:             cfg,
		prefilter:          *ahocorasick.NewTrieBuilder().AddStrings(maps.Keys(cfg.Keywords)).Build(),
		Sema:               semgroup.NewGroup(context.Background(), 40),
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
	logging.Debug().Msgf("found .gitleaksignore file: %s", gitleaksIgnorePath)
	file, err := os.Open(gitleaksIgnorePath)
	if err != nil {
		return err
	}
	defer func() {
		// https://github.com/securego/gosec/issues/512
		if err := file.Close(); err != nil {
			logging.Warn().Msgf("Error closing .gitleaksignore file: %s\n", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	replacer := strings.NewReplacer("\\", "/")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip lines that start with a comment
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize the path.
		// TODO: Make this a breaking change in v9.
		s := strings.Split(line, ":")
		switch len(s) {
		case 3:
			// Global fingerprint.
			// `file:rule-id:start-line`
			s[0] = replacer.Replace(s[0])
		case 4:
			// Commit fingerprint.
			// `commit:file:rule-id:start-line`
			s[1] = replacer.Replace(s[1])
		default:
			logging.Warn().Str("fingerprint", line).Msg("Invalid .gitleaksignore entry")
		}

		// If glob, add entry
		if strings.Contains(line, "*") {
			entry := globIgnoreEntry{}
			if len(s) == 3 {
				// Global fingerprint.
				// `file:rule-id:start-line`
				entry.Commit = "*"
				entry.File = s[0]
				entry.Rule = s[1]
				entry.Line = s[2]

			} else {
				// Commit fingerprint.
				// `commit:file:rule-id:start-line`
				entry.Commit = s[0]
				entry.File = s[1]
				entry.Rule = s[2]
				entry.Line = s[3]
			}

			// Determine which fields are globs
			if entry.Commit == "*" {
				entry.CommitIsGlob = true
			}
			if entry.File == "*" {
				entry.FileIsGlob = true
			}
			if entry.Rule == "*" {
				entry.RuleIsGlob = true
			}
			if entry.Line == "*" {
				entry.LineIsGlob = true
			}

			d.gitleaksGlobIgnore = append(d.gitleaksGlobIgnore, entry)
		} else {
			// Non-glob ignore match
			d.gitleaksIgnore[strings.Join(s, ":")] = struct{}{}
		}

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
	if fragment.Bytes == nil {
		d.TotalBytes.Add(uint64(len(fragment.Raw)))
	}
	d.TotalBytes.Add(uint64(len(fragment.Bytes)))

	var (
		findings []report.Finding
		logger   = func() zerolog.Logger {
			l := logging.With().Str("path", fragment.FilePath)
			if fragment.CommitSHA != "" {
				l = l.Str("commit", fragment.CommitSHA)
			}
			return l.Logger()
		}()
	)

	// check if filepath is allowed
	if fragment.FilePath != "" {
		// is the path our config or baseline file?
		if fragment.FilePath == d.Config.Path || (d.baselinePath != "" && fragment.FilePath == d.baselinePath) {
			logging.Trace().Msg("skipping file: matches config or baseline path")
			return findings
		}
	}
	// check if commit or filepath is allowed.
	if isAllowed, event := checkCommitOrPathAllowed(logger, fragment, d.Config.Allowlists); isAllowed {
		event.Msg("skipping file: global allowlist")
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = newLineRegexp.FindAllStringIndex(fragment.Raw, -1)

	// setup variables to handle different decoding passes
	currentRaw := fragment.Raw
	encodedSegments := []*codec.EncodedSegment{}
	currentDecodeDepth := 0
	decoder := codec.NewDecoder()

	for {
		// build keyword map for prefiltering rules
		keywords := make(map[string]bool)
		normalizedRaw := strings.ToLower(currentRaw)
		matches := d.prefilter.MatchString(normalizedRaw)
		for _, m := range matches {
			keywords[normalizedRaw[m.Pos():int(m.Pos())+len(m.Match())]] = true
		}

		for _, rule := range d.Config.Rules {
			if len(rule.Keywords) == 0 {
				// if no keywords are associated with the rule always scan the
				// fragment using the rule
				findings = append(findings, d.detectRule(fragment, currentRaw, rule, encodedSegments)...)
				continue
			}

			// check if keywords are in the fragment
			for _, k := range rule.Keywords {
				if _, ok := keywords[strings.ToLower(k)]; ok {
					findings = append(findings, d.detectRule(fragment, currentRaw, rule, encodedSegments)...)
					break
				}
			}
		}

		// increment the depth by 1 as we start our decoding pass
		currentDecodeDepth++

		// stop the loop if we've hit our max decoding depth
		if currentDecodeDepth > d.MaxDecodeDepth {
			break
		}

		// decode the currentRaw for the next pass
		currentRaw, encodedSegments = decoder.Decode(currentRaw, encodedSegments)

		// stop the loop when there's nothing else to decode
		if len(encodedSegments) == 0 {
			break
		}
	}

	return filter(findings, d.Redact)
}

// detectRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectRule(fragment Fragment, currentRaw string, r config.Rule, encodedSegments []*codec.EncodedSegment) []report.Finding {
	var (
		findings []report.Finding
		logger   = func() zerolog.Logger {
			l := logging.With().Str("rule-id", r.RuleID).Str("path", fragment.FilePath)
			if fragment.CommitSHA != "" {
				l = l.Str("commit", fragment.CommitSHA)
			}
			return l.Logger()
		}()
	)

	// check if commit or file is allowed for this rule.
	if isAllowed, event := checkCommitOrPathAllowed(logger, fragment, r.Allowlists); isAllowed {
		event.Msg("skipping file: rule allowlist")
		return findings
	}

	if r.Path != nil {
		if r.Regex == nil && len(encodedSegments) == 0 {
			// Path _only_ rule
			if r.Path.MatchString(fragment.FilePath) || (fragment.WindowsFilePath != "" && r.Path.MatchString(fragment.WindowsFilePath)) {
				finding := report.Finding{
					RuleID:      r.RuleID,
					Description: r.Description,
					File:        fragment.FilePath,
					SymlinkFile: fragment.SymlinkFile,
					Match:       fmt.Sprintf("file detected: %s", fragment.FilePath),
					Tags:        r.Tags,
				}
				return append(findings, finding)
			}
		} else {
			// if path is set _and_ a regex is set, then we need to check both
			// so if the path does not match, then we should return early and not
			// consider the regex
			if !(r.Path.MatchString(fragment.FilePath) || (fragment.WindowsFilePath != "" && r.Path.MatchString(fragment.WindowsFilePath))) {
				return findings
			}
		}
	}

	// if path only rule, skip content checks
	if r.Regex == nil {
		return findings
	}

	// if flag configure and raw data size bigger then the flag
	if d.MaxTargetMegaBytes > 0 {
		rawLength := len(currentRaw) / 1000000
		if rawLength > d.MaxTargetMegaBytes {
			logger.Debug().
				Int("size", rawLength).
				Int("max-size", d.MaxTargetMegaBytes).
				Msg("skipping fragment: size")
			return findings
		}
	}

	// use currentRaw instead of fragment.Raw since this represents the current
	// decoding pass on the text
	for _, matchIndex := range r.Regex.FindAllStringIndex(currentRaw, -1) {
		// Extract secret from match
		secret := strings.Trim(currentRaw[matchIndex[0]:matchIndex[1]], "\n")

		// For any meta data from decoding
		var metaTags []string
		currentLine := ""

		// Check if the decoded portions of the segment overlap with the match
		// to see if its potentially a new match
		if len(encodedSegments) > 0 {
			segments := codec.SegmentsWithDecodedOverlap(encodedSegments, matchIndex[0], matchIndex[1])
			if len(segments) == 0 {
				// This item has already been added to a finding
				continue
			}

			matchIndex = codec.AdjustMatchIndex(segments, matchIndex)
			metaTags = append(metaTags, codec.Tags(segments)...)
			currentLine = codec.CurrentLine(segments, currentRaw)
		} else {
			// Fixes: https://github.com/gitleaks/gitleaks/issues/1352
			// removes the incorrectly following line that was detected by regex expression '\n'
			matchIndex[1] = matchIndex[0] + len(secret)
		}

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		loc := location(fragment, matchIndex)

		if matchIndex[1] > loc.endLineIndex {
			loc.endLineIndex = matchIndex[1]
		}

		finding := report.Finding{
			RuleID:      r.RuleID,
			Description: r.Description,
			StartLine:   loc.startLine,
			EndLine:     loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Line:        fragment.Raw[loc.startLineIndex:loc.endLineIndex],
			Match:       secret,
			Secret:      secret,
			File:        fragment.FilePath,
			SymlinkFile: fragment.SymlinkFile,
			Tags:        append(r.Tags, metaTags...),
		}

		if !d.IgnoreGitleaksAllow && strings.Contains(finding.Line, gitleaksAllowSignature) {
			logger.Trace().
				Str("finding", finding.Secret).
				Msg("skipping finding: 'gitleaks:allow' signature")
			continue
		}

		if currentLine == "" {
			currentLine = finding.Line
		}

		// Set the value of |secret|, if the pattern contains at least one capture group.
		// (The first element is the full match, hence we check >= 2.)
		groups := r.Regex.FindStringSubmatch(finding.Secret)
		if len(groups) >= 2 {
			if r.SecretGroup > 0 {
				if len(groups) <= r.SecretGroup {
					// Config validation should prevent this
					continue
				}
				finding.Secret = groups[r.SecretGroup]
			} else {
				// If |secretGroup| is not set, we will use the first suitable capture group.
				for _, s := range groups[1:] {
					if len(s) > 0 {
						finding.Secret = s
						break
					}
				}
			}
		}

		// check entropy
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)
		if r.Entropy != 0.0 {
			// entropy is too low, skip this finding
			if entropy <= r.Entropy {
				logger.Trace().
					Str("finding", finding.Secret).
					Float32("entropy", finding.Entropy).
					Msg("skipping finding: low entropy")
				continue
			}
		}

		// check if the result matches any of the global allowlists.
		if isAllowed, event := checkFindingAllowed(logger, finding, fragment, currentLine, d.Config.Allowlists); isAllowed {
			event.Msg("skipping finding: global allowlist")
			continue
		}

		// check if the result matches any of the rule allowlists.
		if isAllowed, event := checkFindingAllowed(logger, finding, fragment, currentLine, r.Allowlists); isAllowed {
			event.Msg("skipping finding: rule allowlist")
			continue
		}
		findings = append(findings, finding)
	}
	return findings
}

// isIgnored checks the ignored list for a global match, then checks the list for a commit-based match
func (d *Detector) isIgnored(commit string, file string, ruleId string, startLine int) (ignored bool, reason string) {

	// exact global
	globalFingerprint := fmt.Sprintf("%s:%s:%d", file, ruleId, startLine)
	if _, globalIgnored := d.gitleaksIgnore[globalFingerprint]; globalIgnored {
		return true, "global"
	}

	// exact commit
	if commit != "" {
		commitFingerprint := fmt.Sprintf("%s:%s", commit, globalFingerprint)
		if _, commitIgnored := d.gitleaksIgnore[commitFingerprint]; commitIgnored {
			return true, "commit"
		}
	}

	// glob match
	for _, glob := range d.gitleaksGlobIgnore {
		if glob.Matches(commit, file, ruleId, startLine) {
			return true, "glob"
		}
	}

	return false, ""
}

// AddFinding synchronously adds a finding to the findings slice
func (d *Detector) AddFinding(finding report.Finding) {
	globalFingerprint := fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	if finding.Commit != "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = globalFingerprint
	}

	// check if we should ignore this finding
	logger := logging.With().Str("finding", finding.Secret).Logger()
	ignored, reason := d.isIgnored(finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	if ignored {
		evt := logger.Debug().Str("fingerprint", globalFingerprint)
		if reason == "global" {
			evt.Msg("skipping finding: global fingerprint")
		} else if reason == "commit" {
			evt.Msgf("skipping finding: fingerprint")
		} else {
			evt.Msgf("skipping finding: other reason")
		}
		return
	}

	if d.baseline != nil && !IsNew(finding, d.Redact, d.baseline) {
		logger.Debug().
			Str("fingerprint", finding.Fingerprint).
			Msgf("skipping finding: baseline")
		return
	}

	d.findingMutex.Lock()
	d.findings = append(d.findings, finding)
	if d.Verbose {
		printFinding(finding, d.NoColor)
	}
	d.findingMutex.Unlock()
}

// Findings returns the findings added to the detector
func (d *Detector) Findings() []report.Finding {
	return d.findings
}

// AddCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}

// checkCommitOrPathAllowed evaluates |fragment| against all provided |allowlists|.
//
// If the match condition is "OR", only commit and path are checked.
// Otherwise, if regexes or stopwords are defined this will fail.
func checkCommitOrPathAllowed(
	logger zerolog.Logger,
	fragment Fragment,
	allowlists []*config.Allowlist,
) (bool, *zerolog.Event) {
	if fragment.FilePath == "" && fragment.CommitSHA == "" {
		return false, nil
	}

	for _, a := range allowlists {
		var (
			isAllowed        bool
			allowlistChecks  []bool
			commitAllowed, _ = a.CommitAllowed(fragment.CommitSHA)
			pathAllowed      = a.PathAllowed(fragment.FilePath) || (fragment.WindowsFilePath != "" && a.PathAllowed(fragment.WindowsFilePath))
		)
		// If the condition is "AND" we need to check all conditions.
		if a.MatchCondition == config.AllowlistMatchAnd {
			if len(a.Commits) > 0 {
				allowlistChecks = append(allowlistChecks, commitAllowed)
			}
			if len(a.Paths) > 0 {
				allowlistChecks = append(allowlistChecks, pathAllowed)
			}
			// These will be checked later.
			if len(a.Regexes) > 0 {
				continue
			}
			if len(a.StopWords) > 0 {
				continue
			}

			isAllowed = allTrue(allowlistChecks)
		} else {
			isAllowed = commitAllowed || pathAllowed
		}
		if isAllowed {
			event := logger.Trace().Str("condition", a.MatchCondition.String())
			if commitAllowed {
				event.Bool("allowed-commit", commitAllowed)
			}
			if pathAllowed {
				event.Bool("allowed-path", pathAllowed)
			}
			return true, event
		}
	}
	return false, nil
}

// checkFindingAllowed evaluates |finding| against all provided |allowlists|.
//
// If the match condition is "OR", only regex and stopwords are run. (Commit and path should be handled separately).
// Otherwise, all conditions are checked.
//
// TODO: The method signature is awkward. I can't think of a better way to log helpful info.
func checkFindingAllowed(
	logger zerolog.Logger,
	finding report.Finding,
	fragment Fragment,
	currentLine string,
	allowlists []*config.Allowlist,
) (bool, *zerolog.Event) {
	for _, a := range allowlists {
		allowlistTarget := finding.Secret
		switch a.RegexTarget {
		case "match":
			allowlistTarget = finding.Match
		case "line":
			allowlistTarget = currentLine
		}

		var (
			checks                 []bool
			isAllowed              bool
			commitAllowed          bool
			commit                 string
			pathAllowed            bool
			regexAllowed           = a.RegexAllowed(allowlistTarget)
			containsStopword, word = a.ContainsStopWord(finding.Secret)
		)
		// If the condition is "AND" we need to check all conditions.
		if a.MatchCondition == config.AllowlistMatchAnd {
			// Determine applicable checks.
			if len(a.Commits) > 0 {
				commitAllowed, commit = a.CommitAllowed(fragment.CommitSHA)
				checks = append(checks, commitAllowed)
			}
			if len(a.Paths) > 0 {
				pathAllowed = a.PathAllowed(fragment.FilePath) || (fragment.WindowsFilePath != "" && a.PathAllowed(fragment.WindowsFilePath))
				checks = append(checks, pathAllowed)
			}
			if len(a.Regexes) > 0 {
				checks = append(checks, regexAllowed)
			}
			if len(a.StopWords) > 0 {
				checks = append(checks, containsStopword)
			}

			isAllowed = allTrue(checks)
		} else {
			isAllowed = regexAllowed || containsStopword
		}

		if isAllowed {
			event := logger.Trace().
				Str("finding", finding.Secret).
				Str("condition", a.MatchCondition.String())
			if commitAllowed {
				event.Str("allowed-commit", commit)
			}
			if pathAllowed {
				event.Bool("allowed-path", pathAllowed)
			}
			if regexAllowed {
				event.Bool("allowed-regex", regexAllowed)
			}
			if containsStopword {
				event.Str("allowed-stopword", word)
			}
			return true, event
		}
	}
	return false, nil
}

func allTrue(bools []bool) bool {
	for _, check := range bools {
		if !check {
			return false
		}
	}
	return true
}
