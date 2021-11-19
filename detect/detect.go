package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Options struct {
	Verbose bool
	Redact  bool
}

func DetectFindings(cfg config.Config, b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding
	linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)

	// check if we should skip file based on the global allowlist
	if cfg.Allowlist.PathAllowed(filePath) {
		return findings
	}

	for _, r := range cfg.Rules {
		if r.Allowlist.CommitAllowed(commit) {
			continue
		}
		if r.Allowlist.PathAllowed(filePath) {
			continue
		}
		matchIndices := r.Regex.FindAllIndex(b, -1)
		for _, m := range matchIndices {
			location := getLocation(linePairs, m[0], m[1])
			f := report.Finding{
				Description: r.Description,
				File:        filePath,
				RuleID:      r.RuleID,
				StartLine:   location.startLine,
				EndLine:     location.endLine,
				StartColumn: location.startColumn,
				EndColumn:   location.endColumn,
				Secret:      strings.Trim(string(b[m[0]:m[1]]), "\n"),
				Context:     limit(strings.Trim(string(b[location.startLineIndex:location.endLineIndex]), "\n")),
			}

			if r.Allowlist.RegexAllowed(f.Secret) {
				continue
			}

			if r.EntropySet() {
				include, entropy := r.IncludeEntropy(strings.Trim(string(b[m[0]:m[1]]), "\n"))
				if include {
					f.Entropy = float32(entropy)
					findings = append(findings, f)
				}
			} else {
				findings = append(findings, f)
			}
		}
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
