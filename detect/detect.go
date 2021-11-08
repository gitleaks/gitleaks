package detect

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Options struct {
	Verbose bool
	Redact  bool
}

// TODO dry up processGitBytes and processBytes

func processGitBytes(cfg config.Config, b []byte, filePath string, commit string) []report.Finding {
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
				RuleID:      r.RuleID,
				StartLine:   location.startLine,
				EndLine:     location.endLine,
				StartColumn: location.startColumn,
				EndColumn:   location.endColumn,
				Content:     string(b[m[0]:m[1]]),
				Line:        string(b[location.startLineIndex:location.endLineIndex]),
			}

			if r.Allowlist.RegexAllowed(f.Content) {
				continue
			}

			findings = append(findings, f)
		}
	}

	return findings
}

func processBytes(cfg config.Config, b []byte, filePath string) []report.Finding {
	var findings []report.Finding
	linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)

	// check if we should skip file based on the global allowlist
	if cfg.Allowlist.PathAllowed(filePath) {
		return findings
	}

	for _, r := range cfg.Rules {
		if r.Allowlist.PathAllowed(filePath) {
			continue
		}
		matchIndices := r.Regex.FindAllIndex(b, -1)
		for _, m := range matchIndices {
			location := getLocation(linePairs, m[0], m[1])
			f := report.Finding{
				RuleID:      r.RuleID,
				StartLine:   location.startLine,
				EndLine:     location.endLine,
				StartColumn: location.startColumn,
				EndColumn:   location.endColumn,
				Content:     string(b[m[0]:m[1]]),
				Line:        string(b[location.startLineIndex:location.endLineIndex]),
			}

			if r.Allowlist.RegexAllowed(f.Content) {
				continue
			}

			findings = append(findings, f)
		}
	}

	return findings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
