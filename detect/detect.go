package detect

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect/git"
	"github.com/zricethezav/gitleaks/v8/report"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/spf13/cobra"
)

// Detector is the main detector struct
type Detector struct {
	// cfg is the configuration for the detector
	cfg config.Config

	redact bool

	verbose bool

	// commitMap is used to keep track of commits that have been scanned.
	// This is only used for logging purposes and git scans.
	commitMap map[string]bool

	// findingMutex is to prevent concurrent access to the
	// findings slice when adding findings.
	findingMutex *sync.Mutex

	findings []report.Finding
}

// Fragment contains the data to be scanned. Other names to consider: segment, section, part
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	// FilePath is the path to the file
	FilePath string

	// CommitSHA is the SHA of the commit
	CommitSHA string

	// RuleID is the ID of the rule that is to be used. If no RuleID is set then the entire
	// rule set will be used
	RuleID string

	newlineIndices [][]int
}

func NewDetector(cfg config.Config) *Detector {
	return &Detector{
		commitMap:    make(map[string]bool),
		findingMutex: &sync.Mutex{},
		findings:     make([]report.Finding, 0),
		cfg:          cfg,
	}
}

func NewDetectorDefaultConfig() *Detector {
	// TODO load default config
	// return NewDetector()
	return nil
}

// Start is called from cmd
func (d *Detector) Start(cmd *cobra.Command) ([]report.Finding, error) {
	var (
		findings []report.Finding
		err      error
	)

	start := time.Now()

	d.cfg.Path, err = cmd.Flags().GetString("config")
	if err != nil {
		return findings, err
	}

	source, err := cmd.Flags().GetString("source")
	if err != nil {
		return findings, err
	}

	// if config path is not set, then use the {source}/.gitleaks.toml path.
	// note that there may not be a `{source}/.gitleaks.toml` file, this is ok.
	if d.cfg.Path == "" {
		d.cfg.Path = filepath.Join(source, ".gitleaks.toml")
	}

	// set verbose flag
	if d.verbose, err = cmd.Flags().GetBool("verbose"); err != nil {
		return findings, err
	}

	// set redact flag
	if d.redact, err = cmd.Flags().GetBool("redact"); err != nil {
		return findings, err
	}

	noGit, err := cmd.Flags().GetBool("no-git")
	if err != nil {
		return findings, err
	}

	if noGit {
		// TODO treat the repo as a directory
	} else {
		// TODO scan git history
		logOpts, err := cmd.Flags().GetString("log-opts")
		if err != nil {
			return findings, err
		}
		// TODO abstract git log to "producer" or "pipe"
		history, err := git.GitLog(source, logOpts)
		if err != nil {
			return findings, err
		}
		d.startGitScan(history)
	}

	log.Info().Msgf("scan completed in %s", time.Since(start))

	// TODO generate report, check exit code, etc
	// exitCode, err := cmd.Flags().GetInt("exit-code")

	return findings, nil
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

	// check if filepath is allowed
	if d.cfg.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.cfg.Path {
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = regexp.MustCompile("\n").FindAllStringIndex(fragment.Raw, -1)

	for _, rule := range d.cfg.Rules {
		findings = append(findings, d.detectRule(fragment, rule)...)
	}
	return filter(findings, d.redact)
}

func (d *Detector) detectRule(fragment Fragment, rule *config.Rule) []report.Finding {
	var findings []report.Finding

	// check if filepath or commit is allowed for this rule
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return findings
	}

	if rule.Path != nil && rule.Regex == nil {
		// Path _only_ rule
		if rule.Path.Match([]byte(fragment.FilePath)) {
			finding := report.Finding{
				Description: rule.Description,
				File:        fragment.FilePath,
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
		if !rule.Path.Match([]byte(fragment.FilePath)) {
			return findings
		}
	}

	matchIndices := rule.Regex.FindAllStringIndex(fragment.Raw, -1)
	for _, matchIndex := range matchIndices {
		// extract secret from match
		secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], " \n")

		// determine location of match. Note that the location
		// in the finding will be the line/column numbers of the _match_
		// not the _secret_, which will be different if the secretGroup
		// value is set for this rule
		loc := location(fragment, matchIndex)

		finding := report.Finding{
			Description: rule.Description,
			File:        fragment.FilePath,
			RuleID:      rule.RuleID,
			StartLine:   loc.startLine,
			EndLine:     loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Secret:      secret,
			Match:       secret,
			Tags:        rule.Tags,
		}

		// check if the secret is in the allowlist
		if rule.Allowlist.RegexAllowed(finding.Secret) ||
			d.cfg.Allowlist.RegexAllowed(finding.Secret) {
			continue
		}

		// extract secret from secret group if set
		if rule.SecretGroup != 0 {
			groups := rule.Regex.FindStringSubmatch(secret)
			if len(groups) <= rule.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				break
			}
			secret = groups[rule.SecretGroup]
			finding.Secret = secret
		}

		// check entropy
		finding.Entropy = float32(shannonEntropy(secret))
		if rule.EntropySet() && finding.Entropy < float32(rule.Entropy) {
			// entropy is too low, skip this finding
			return findings
		}

		findings = append(findings, finding)
	}
	return findings
}

func (d *Detector) startGitScan(gitdiffFiles <-chan *gitdiff.File) {
	s := semgroup.NewGroup(context.Background(), 4)

	for f := range gitdiffFiles {
		f := f

		// skip binary files
		if f.IsBinary || f.IsDelete {
			continue
		}

		// Check if commit is allowed
		commitSHA := ""
		if f.PatchHeader != nil {
			commitSHA = f.PatchHeader.SHA
			if d.cfg.Allowlist.CommitAllowed(f.PatchHeader.SHA) {
				continue
			}
		}
		d.addCommit(commitSHA)

		s.Go(func() error {
			for _, textFragment := range f.TextFragments {
				if textFragment == nil {
					return nil
				}

				fragment := Fragment{
					Raw:       textFragment.Raw(gitdiff.OpAdd),
					CommitSHA: commitSHA,
					FilePath:  f.NewName,
				}

				for _, finding := range d.Detect(fragment) {
					d.addFinding(augmentGitFinding(finding, textFragment, f))
				}
			}
			return nil
		})
	}

	if err := s.Wait(); err != nil {
		fmt.Println(err)
	}
}

func (d *Detector) startFileScan(source string) []report.Finding {
	var findings []report.Finding
	s := semgroup.NewGroup(context.Background(), 4)
	paths := make(chan string)
	s.Go(func() error {
		defer close(paths)
		return filepath.Walk(source,
			func(path string, fInfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fInfo.Name() == ".git" {
					return filepath.SkipDir
				}
				if fInfo.Mode().IsRegular() {
					paths <- path
				}
				return nil
			})
	})
	for pa := range paths {
		p := pa
		s.Go(func() error {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			fragment := Fragment{
				Raw:      string(b),
				FilePath: p,
			}
			for _, finding := range d.Detect(fragment) {
				d.addFinding(finding)
			}

			return nil
		})
	}

	return findings
}

// addFinding synchronously adds a finding to the findings slice
func (d *Detector) addFinding(finding report.Finding) {
	d.findingMutex.Lock()
	d.findings = append(d.findings, finding)
	if d.verbose {
		printFinding(finding)
	}
	d.findingMutex.Unlock()
}

// addCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}
