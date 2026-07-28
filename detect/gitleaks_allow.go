package detect

import (
	"strconv"
	"strings"

	"github.com/zricethezav/gitleaks/v8/regexp"
)

const (
	gitleaksAllowSignature     = "gitleaks:allow"
	gitleaksAllowLineSignature = "gitleaks:allow_line:"
)

var gitleaksAllowLineRegexp = regexp.MustCompile(gitleaksAllowLineSignature + `([+-][0-9]+)\b`)

// gitleaksAllowLineTargets returns the zero-based line numbers targeted by
// gitleaks:allow_line directives in raw.
func gitleaksAllowLineTargets(raw string) map[int]struct{} {
	if !strings.Contains(raw, gitleaksAllowLineSignature) {
		return nil
	}

	lines := strings.Split(raw, "\n")
	targets := make(map[int]struct{})

	for lineNumber, line := range lines {
		for _, match := range gitleaksAllowLineRegexp.FindAllStringSubmatch(line, -1) {
			offset, err := strconv.Atoi(match[1])
			if err != nil {
				continue
			}

			target := lineNumber + offset
			if target >= 0 && target < len(lines) {
				targets[target] = struct{}{}
			}
		}
	}

	return targets
}

func containsGitleaksAllow(line string) bool {
	for {
		index := strings.Index(line, gitleaksAllowSignature)
		if index == -1 {
			return false
		}

		suffix := line[index+len(gitleaksAllowSignature):]
		if !strings.HasPrefix(suffix, "_line:") {
			return true
		}

		line = suffix[len("_line:"):]
	}
}

func isGitleaksAllowed(line string, startLine, endLine int, allowLineTargets map[int]struct{}) bool {
	if containsGitleaksAllow(line) {
		return true
	}

	for lineNumber := startLine; lineNumber <= endLine; lineNumber++ {
		if _, ok := allowLineTargets[lineNumber]; ok {
			return true
		}
	}

	return false
}
