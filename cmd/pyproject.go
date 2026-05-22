package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// pyprojectFilename is the conventional Python project metadata file name.
// gitleaks reads its own configuration from a [tool.gitleaks] sub-table when
// pointed at one of these (or when one is auto-discovered alongside
// .gitleaks.toml).
const pyprojectFilename = "pyproject.toml"

// errNoGitleaksTable is returned when a pyproject.toml is parseable but does
// not contain a [tool.gitleaks] sub-table.
var errNoGitleaksTable = errors.New("pyproject.toml has no [tool.gitleaks] section")

// isPyprojectPath reports whether path looks like a pyproject.toml (matches
// case-insensitively on the basename so users on case-insensitive filesystems
// don't get surprised).
func isPyprojectPath(path string) bool {
	return strings.EqualFold(filepath.Base(path), pyprojectFilename)
}

// extractGitleaksFromPyproject reads pyproject.toml from path, isolates the
// [tool.gitleaks] sub-table, and returns it re-marshalled as standalone TOML
// suitable for feeding directly to viper. The structure of the [tool.gitleaks]
// section is otherwise unchanged — every key supported by .gitleaks.toml is
// supported here verbatim.
func extractGitleaksFromPyproject(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// Parse into a generic map first, then walk to [tool.gitleaks].
	var doc map[string]any
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	tool, ok := doc["tool"].(map[string]any)
	if !ok {
		return nil, errNoGitleaksTable
	}
	cfg, ok := tool["gitleaks"].(map[string]any)
	if !ok {
		return nil, errNoGitleaksTable
	}

	out, err := toml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("re-marshal [tool.gitleaks] from %s: %w", path, err)
	}
	return out, nil
}
