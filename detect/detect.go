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

func processBytes(cfg config.Config, b []byte, ext string) []report.Finding {
	var findings []report.Finding
	linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)
	for _, r := range cfg.Rules {
		matchIndices := r.RegexCompiled.FindAllIndex(b, -1)
		for _, m := range matchIndices {
			location := getLocation(linePairs, m[0], m[1])
			f := report.Finding{
				StartLine:   location.startLine,
				EndLine:     location.endLine,
				StartColumn: location.startColumn,
				EndColumn:   location.endColumn,
				Content:     string(b[m[0]:m[1]]),
				Line:        string(b[location.startLineIndex:location.endLineIndex]),
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

func FromPipe() {

}

func FromSQL() {

}
