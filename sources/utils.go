package sources

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/version"
)

var httpClient *http.Client
var defaultUserAgent string

func init() {
	if version.Version == version.DefaultMsg {
		defaultUserAgent = "Gitleaks/src-build"
	} else {
		defaultUserAgent = "Gitleaks/" + version.Version
	}
}

type customRoundTripper struct {
	rt http.RoundTripper
}

// pathSplitAll takes a path with '/' and '!' separators and splits it into its
// components
func pathSplitAll(path string) []string {
	path = filepath.ToSlash(path)
	seps := "/" + InnerPathSeparator
	components := []string{}
	size := len(path)
	start := 0

	for i, c := range path {
		if strings.ContainsRune(seps, c) {
			if i-start > 0 {
				components = append(components, path[start:i])
			}
			start = i + 1
		} else if i == size-1 && size-start > 0 {
			components = append(components, path[start:size])
		}
	}

	return components
}

// pathGlobMatch does basic glob matching. It is similar to filepath.Match except
// it currently only supports wildcards (*) and recursive wildcards (**), which
// is not supported by filepath.Match
func pathGlobMatch(pattern, path string) bool {
	patternParts := pathSplitAll(pattern)
	pathParts := pathSplitAll(path)
	return matchParts(patternParts, pathParts)
}

func matchParts(patternParts, pathParts []string) bool {
	pIdx, ptIdx := 0, 0

	for pIdx < len(patternParts) && ptIdx < len(pathParts) {
		switch patternParts[pIdx] {
		case "*": // Match a single segment
			// Move to next part of both the pattern and path
			pIdx++
			ptIdx++
		case "**": // Match zero or more segments
			// If this is the last pattern part, we match the rest of the path
			if pIdx == len(patternParts)-1 {
				return true
			}
			// Try matching subsequent parts
			for i := ptIdx; i <= len(pathParts); i++ {
				if matchParts(patternParts[pIdx+1:], pathParts[i:]) {
					return true
				}
			}

			return false
		default:
			// Exact match required for this segment
			if patternParts[pIdx] != pathParts[ptIdx] {
				return false
			}
			pIdx++
			ptIdx++
		}
	}

	// Both pattern and path should be fully consumed for a match
	return pIdx == len(patternParts) && ptIdx == len(pathParts)
}

// NewHTTPClient creates an http client with preferred configuration
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &customRoundTripper{
			rt: http.DefaultTransport,
		},
	}
}

func (rt *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())

	if len(req.Header.Get("User-Agent")) == 0 {
		req.Header.Set("User-Agent", defaultUserAgent)
	}

	return rt.rt.RoundTrip(req)
}
