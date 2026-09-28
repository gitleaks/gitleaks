package detect

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/report"
)

func TestGitleaksIgnoreV2OnlySuppressesTheSameSecret(t *testing.T) {
	oldSecret := report.Finding{File: "config.py", RuleID: "generic-api-key", StartLine: 1, Secret: "old-secret"}
	ignorePath := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignorePath, []byte(oldSecret.NewFingerprintV2()+"\n"), 0o600))

	d := &Detector{gitleaksIgnore: make(map[string]struct{}), findingMutex: &sync.Mutex{}}
	d.UseFingerprintV2 = true
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))
	d.AddFinding(oldSecret)
	d.AddFinding(report.Finding{File: "config.py", RuleID: "generic-api-key", StartLine: 1, Secret: "replacement-secret"})

	findings := d.Findings()
	require.Len(t, findings, 1)
	require.Equal(t, "replacement-secret", findings[0].Secret)
	require.NotEmpty(t, findings[0].FingerprintV2)
	require.NotContains(t, findings[0].FingerprintV2, findings[0].Secret)
	require.NotEqual(t, oldSecret.NewFingerprintV2(), findings[0].FingerprintV2)
}

func TestGitleaksIgnoreV2RejectsMalformedEntry(t *testing.T) {
	ignorePath := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignorePath, []byte("v2:not-a-hash\n"), 0o600))
	d := &Detector{gitleaksIgnore: make(map[string]struct{})}
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))
	require.Empty(t, d.gitleaksIgnore)
}

func TestLegacyGitleaksIgnoreRetainsLocationWideBehavior(t *testing.T) {
	ignorePath := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignorePath, []byte("config.py:generic-api-key:1\n"), 0o600))
	d := &Detector{gitleaksIgnore: make(map[string]struct{}), findingMutex: &sync.Mutex{}}
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))
	d.AddFinding(report.Finding{File: "config.py", RuleID: "generic-api-key", StartLine: 1, Secret: "replacement-secret"})
	require.Empty(t, d.Findings())
}

func TestFingerprintV2DoesNotApplyLegacyLocationWideIgnores(t *testing.T) {
	ignorePath := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(ignorePath, []byte("config.py:generic-api-key:1\n"), 0o600))
	d := &Detector{gitleaksIgnore: make(map[string]struct{}), findingMutex: &sync.Mutex{}, UseFingerprintV2: true}
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))
	d.AddFinding(report.Finding{File: "config.py", RuleID: "generic-api-key", StartLine: 1, Secret: "replacement-secret"})
	require.Len(t, d.Findings(), 1)
	require.Equal(t, "replacement-secret", d.Findings()[0].Secret)
}

func TestFingerprintV2HasVersionPrefix(t *testing.T) {
	fingerprint := (report.Finding{File: "config.py", RuleID: "generic-api-key", StartLine: 1, Secret: "secret"}).NewFingerprintV2()
	require.True(t, strings.HasPrefix(fingerprint, "v2:"))
	require.True(t, isValidFingerprintV2(fingerprint))
}

func TestFingerprintV2IsComputedBeforeRedaction(t *testing.T) {
	content := `aws_token = "AKIALALEMEL33243OLIA"`
	plain, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	plain.UseFingerprintV2 = true
	plainFindings := plain.DetectString(content)
	require.NotEmpty(t, plainFindings)

	redacted, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	redacted.UseFingerprintV2 = true
	redacted.Redact = 100
	redactedFindings := redacted.DetectString(content)
	require.NotEmpty(t, redactedFindings)
	require.Equal(t, "REDACTED", redactedFindings[0].Secret)
	require.Equal(t, plainFindings[0].FingerprintV2, redactedFindings[0].FingerprintV2)
}
