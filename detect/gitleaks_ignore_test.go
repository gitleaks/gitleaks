package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestUnusedGitleaksIgnoreEntries(t *testing.T) {
	d := NewDetector(config.Config{})

	used := "api.go:aws-access-key:7"
	stale := "gone.go:aws-access-key:1"
	d.gitleaksIgnore[used] = struct{}{}
	d.gitleaksIgnore[stale] = struct{}{}

	d.AddFinding(report.Finding{
		File:      "api.go",
		RuleID:    "aws-access-key",
		StartLine: 7,
		Secret:    "AKIALALEMEL33243OLIA",
	})

	require.Empty(t, d.Findings(), "matching ignore should suppress the finding")

	unused := d.UnusedGitleaksIgnoreEntries()
	assert.Equal(t, []string{stale}, unused)
}

func TestUnusedGitleaksIgnoreEntries_CommitFingerprint(t *testing.T) {
	d := NewDetector(config.Config{})

	used := "abc123:api.go:aws-access-key:7"
	stale := "abc123:other.go:aws-access-key:1"
	d.gitleaksIgnore[used] = struct{}{}
	d.gitleaksIgnore[stale] = struct{}{}

	d.AddFinding(report.Finding{
		Commit:    "abc123",
		File:      "api.go",
		RuleID:    "aws-access-key",
		StartLine: 7,
		Secret:    "AKIALALEMEL33243OLIA",
	})

	require.Empty(t, d.Findings())
	assert.Equal(t, []string{stale}, d.UnusedGitleaksIgnoreEntries())
}

func TestUnusedGitleaksIgnoreEntries_None(t *testing.T) {
	d := NewDetector(config.Config{})
	assert.Empty(t, d.UnusedGitleaksIgnoreEntries())
}
