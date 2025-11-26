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
func pathGlobMatch(glob, path string) bool {
	globParts := pathSplitAll(glob)
	pathParts := pathSplitAll(path)
	return matchParts(globParts, pathParts)
}

func matchParts(globParts, pathParts []string) bool {
	globIndex, pathIndex := 0, 0

	for globIndex < len(globParts) && pathIndex < len(pathParts) {
		switch globParts[globIndex] {
		case "*": // Match a single segment
			// Move to next part of both the glob and path
			globIndex++
			pathIndex++
		case "**": // Match zero or more segments
			// If this is the last glob part, we match the rest of the path
			if globIndex == len(globParts)-1 {
				return true
			}
			// Try matching subsequent parts
			for i := pathIndex; i <= len(pathParts); i++ {
				if matchParts(globParts[globIndex+1:], pathParts[i:]) {
					return true
				}
			}
			return false
		default:
			// Exact match required for this segment
			if globParts[globIndex] != pathParts[pathIndex] {
				return false
			}
			globIndex++
			pathIndex++
		}
	}

	// Both glob and path should be fully consumed for a match
	return globIndex == len(globParts) && pathIndex == len(pathParts)
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
