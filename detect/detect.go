package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Options struct {
	Verbose bool
	Redact  bool
}

const MAXGOROUTINES = 4

func DetectFindings(cfg config.Config, b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding
	linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)

	// check if we should skip file based on the global allowlist or if the file is the same as the gitleaks config
	if cfg.Allowlist.PathAllowed(filePath) || filePath == cfg.Path {
		return findings
	}

	for _, r := range cfg.Rules {
		pathSkip := false
		if r.Allowlist.CommitAllowed(commit) {
			continue
		}
		if r.Allowlist.PathAllowed(filePath) {
			continue
		}

		// Check if path should be considered
		if r.Path != nil {
			if r.Path.Match([]byte(filePath)) {
				if r.Regex == nil {
					// This is a path only rule
					f := report.Finding{
						Description: r.Description,
						File:        filePath,
						RuleID:      r.RuleID,
						Match:       fmt.Sprintf("file detected: %s", filePath),
						Tags:        r.Tags,
					}
					findings = append(findings, f)
					pathSkip = true
				}
			} else {
				pathSkip = true
			}
		}
		if pathSkip {
			continue
		}

		matchIndices := r.Regex.FindAllIndex(b, -1)
		for _, m := range matchIndices {
			location := getLocation(linePairs, m[0], m[1])
			secret := strings.Trim(string(b[m[0]:m[1]]), "\n")
			f := report.Finding{
				Description: r.Description,
				File:        filePath,
				RuleID:      r.RuleID,
				StartLine:   location.startLine,
				EndLine:     location.endLine,
				StartColumn: location.startColumn,
				EndColumn:   location.endColumn,
				Secret:      secret,
				Match:       secret,
				Tags:        r.Tags,
			}

			if r.Allowlist.RegexAllowed(f.Secret) || cfg.Allowlist.RegexAllowed(f.Secret) {
				continue
			}

			// extract secret from secret group if set
			if r.SecretGroup != 0 {
				groups := r.Regex.FindStringSubmatch(secret)
				if len(groups)-1 > r.SecretGroup || len(groups) == 0 {
					// Config validation should prevent this
					break
				}
				secret = groups[r.SecretGroup]
				f.Secret = secret
			}

			// extract secret from secret group if set
			if r.EntropySet() {
				include, entropy := r.IncludeEntropy(secret)
				if include {
					f.Entropy = float32(entropy)
					findings = append(findings, f)
				}
			} else {
				findings = append(findings, f)
			}
		}
	}

	return dedupe(findings)
}

func ValidateExamples(cfg config.Config, ruleID string) []report.Finding {
	var findings []report.Finding

	if ruleID != "" {
		for _, r := range cfg.Rules {
			if r.RuleID == ruleID {
				cfg.Rules = []*config.Rule{r}
				break
			}
		}
	}

	for _, r := range cfg.Rules {
		for _, eg := range r.Examples {
			b := []byte(eg)
			linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)
			matchIndices := r.Regex.FindAllIndex(b, -1)
			for _, m := range matchIndices {
				location := getLocation(linePairs, m[0], m[1])
				secret := strings.Trim(string(b[m[0]:m[1]]), "\n")
				f := report.Finding{
					Description: r.Description,
					File:        cfg.Path,
					RuleID:      r.RuleID,
					StartLine:   location.startLine,
					EndLine:     location.endLine,
					StartColumn: location.startColumn,
					EndColumn:   location.endColumn,
					Secret:      secret,
					Match:       secret,
					Tags:        r.Tags,
				}

				if r.Allowlist.RegexAllowed(f.Secret) || cfg.Allowlist.RegexAllowed(f.Secret) {
					continue
				}

				// extract secret from secret group if set
				if r.SecretGroup != 0 {
					groups := r.Regex.FindStringSubmatch(secret)
					if len(groups)-1 > r.SecretGroup || len(groups) == 0 {
						// Config validation should prevent this
						break
					}
					secret = groups[r.SecretGroup]
					f.Secret = secret
				}

				// extract secret from secret group if set
				if r.EntropySet() {
					include, entropy := r.IncludeEntropy(secret)
					if include {
						f.Entropy = float32(entropy)
						findings = append(findings, f)
					}
				} else {
					findings = append(findings, f)
				}
			}
		}

	}
	findings = dedupe(findings)

	for _, v := range findings {
		printFinding(v)
	}

	return findings
}

func limit(s string) string {
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}

func dedupe(findings []report.Finding) []report.Finding {
	var retFindings []report.Finding
	for _, f := range findings {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.EndLine == fPrime.EndLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.Replace(f.Match, f.Secret, "REDACTED", -1)
					betterMatch := strings.Replace(fPrime.Match, fPrime.Secret, "REDACTED", -1)
					log.Debug().Msgf("skipping %s finding (%s), %s rule takes precendence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}

	return retFindings
}
