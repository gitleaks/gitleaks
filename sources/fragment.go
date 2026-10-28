package sources

import (
	"path/filepath"
	"strings"
)

// Fragment represents a fragment of a source with its meta data
type Fragment struct {
	// Raw is the raw content of the fragment
	Raw string

	Bytes []byte

	// FilePath is the path to the file if applicable.
	// The path separator MUST be normalized to `/`.
	FilePath    string
	SymlinkFile string
	// WindowsFilePath is the path with the original separator.
	// This provides a backwards-compatible solution to https://github.com/gitleaks/gitleaks/issues/1565.
	WindowsFilePath string `json:"-"` // TODO: remove this in v9.

	// Root is the directory a file scan was rooted at, or "" when the fragment
	// did not come from one. FilePath is spelled the way the root was given
	// (`gitleaks dir /abs/path` reports `/abs/path/src/x.py`), so allowlist
	// paths, .gitleaksignore fingerprints and the config/baseline self-skip
	// are also matched against FilePath relative to Root, the way git scans
	// match against repository-relative paths.
	Root string `json:"-"`

	// CommitSHA is the SHA of the commit if applicable
	CommitSHA string // TODO: remove this in v9 and use CommitInfo instead

	// StartLine is the line number this fragment starts on
	StartLine int

	// CommitInfo captures additional information about the git commit if applicable
	CommitInfo *CommitInfo

	InheritedFromFinding bool // Indicates if this fragment is inherited from a finding
}

// RootRelativePath returns FilePath relative to Root with `/` separators, or
// "" when the fragment has no root or the file sits outside it. An archive
// member keeps its inner path: `dir.tar!inner/file` stays after the outer
// path is made relative.
func RootRelativePath(root, filePath string) string {
	if root == "" || filePath == "" {
		return ""
	}
	outer, inner, nested := strings.Cut(filePath, InnerPathSeparator)
	rel, err := filepath.Rel(root, filepath.FromSlash(outer))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if nested {
		return rel + InnerPathSeparator + inner
	}
	return rel
}
