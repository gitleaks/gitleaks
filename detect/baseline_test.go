package detect

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
)

func TestIsNew(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		findings report.Finding
		redact   uint
		baseline []report.Finding
		expect   bool
	}{
		// new
		"new - commit doesn't match baseline": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
			},
			baseline: []report.Finding{
				{
					Commit: "0002",
					Author: "a",
				},
			},
			expect: true,
		},
		"new - redacted, different baseline": {
			findings: report.Finding{
				RuleID:      "private-key",
				Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
				StartLine:   1,
				EndLine:     15,
				StartColumn: 1,
				EndColumn:   30,
				Match:       "REDACTED",
				Secret:      "REDACTED",
				File:        "key.txt",
				Commit:      "6d3ba1f7653822c0f8ac9a9af56daaa2cd8bbcad",
				Entropy:     5.9834013,
				Author:      "James Bond",
				Email:       "jbond@gov.co.uk",
				Date:        "2025-03-02T15:10:40Z",
				Message:     "init",
				Fingerprint: "6d3ba1f7653822c0f8ac9a9af56daaa2cd8bbcad:key.txt:private-key:1",
			},
			baseline: []report.Finding{
				{
					RuleID:      "private-key",
					Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
					StartLine:   1,
					EndLine:     15,
					StartColumn: 1,
					EndColumn:   30,
					Match:       "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
					File:        "key.txt",
					Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
					Entropy:     5.9834013,
					Author:      "James Bond",
					Email:       "jbond@gov.co.uk",
					Date:        "2025-02-02T17:45:30Z",
					Message:     "init",
					Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
				},
			},
			expect: true,
		},

		"new - redact on, baseline holds a different raw secret": {
			findings: report.Finding{
				RuleID: "generic-api-key",
				Match:  `api_key = "rotated-secret-value"`,
				Secret: "rotated-secret-value",
				File:   "config.py",
			},
			redact: 100,
			baseline: []report.Finding{
				{
					RuleID: "generic-api-key",
					Match:  `api_key = "original-secret-value"`,
					Secret: "original-secret-value",
					File:   "config.py",
				},
			},
			expect: true,
		},
		"new - redact on, partially redacted baseline, rotated secret": {
			findings: report.Finding{
				RuleID: "generic-api-key",
				Match:  `api_key = "rotated-secret-value"`,
				Secret: "rotated-secret-value",
				File:   "config.py",
			},
			redact: 25,
			baseline: []report.Finding{
				{
					RuleID: "generic-api-key",
					// baseline written with --redact=25: first 75% of the secret kept
					Match:  `api_key = "original-secret-..."`,
					Secret: "original-secret-...",
					File:   "config.py",
				},
			},
			expect: true,
		},
		"not new - redact on, partially redacted baseline, same secret": {
			findings: report.Finding{
				RuleID: "generic-api-key",
				Match:  `api_key = "original-secret-value"`,
				Secret: "original-secret-value",
				File:   "config.py",
			},
			redact: 25,
			baseline: []report.Finding{
				{
					RuleID: "generic-api-key",
					Match:  `api_key = "original-secret-..."`,
					Secret: "original-secret-...",
					File:   "config.py",
				},
			},
			expect: false,
		},

		// not new
		"not new - commit+author matches": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
			},
			baseline: []report.Finding{
				{
					Commit: "0000",
					Author: "a",
				},
			},
			expect: false,
		},
		"not new - commit+author matches, tags ignored": {
			findings: report.Finding{
				Commit: "0000",
				Author: "a",
				Tags:   []string{"a", "b"},
			},
			baseline: []report.Finding{
				{
					Commit: "0000",
					Author: "a",
					Tags:   []string{"a", "c"},
				},
			},
			expect: false, // Updated tags doesn't make it a new finding
		},
		// The previous version of this case modeled an already-redacted
		// finding compared against a raw baseline. That input cannot occur
		// in the fixed flow: the baseline is now checked in DetectContext
		// before redaction, so IsNew always sees the raw finding. This
		// case pins the real flow instead: a raw finding against a
		// baseline written with --redact (placeholder values), which must
		// still suppress the finding (#1441).
		"not new - redact 100, baseline holds the redacted placeholder, same secret": {
			findings: report.Finding{
				RuleID:      "private-key",
				Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
				StartLine:   1,
				EndLine:     15,
				StartColumn: 1,
				EndColumn:   30,
				Match:       "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
				Secret:      "-----BEGIN RSA PRIVATE KEY-----\nMIICWgIBAAKBgFIckgeuo80H6skLd1FKYfJC75/tnmtDWO4Rf2AFqrYZdu71VKGR\noGfEVl7AmvxTd9u6tnPtWjAeu9k2VMQcOtXEwgU0A6H09EBcS1EVN/I8pcNw1qjO\nkJ7ZA8AhZk/OpVAK7665CEny7ISRNZnx1nPaHjlb8lebPzlWOvxX9wjbAgMBAAEC\ngYBN6wqv+4s4juC/cwAAxeL4L4iQbL497yS+lSAYEIiUUMnJrEhpIXXjwi5rr73i\n35oHisCEdaF1tFRxpNr/VgKFsM1KqQUZvCVRE9Rokfe23QkQDvcxh9CI/Ah9Eofp\nx/m5DjSsRKrbIpOOAC3J3B/s02HRmxy8tRYnQVqWXzAH8QJBAJdBgXi62KI1eytU\n7l3Q8ymkS1OHzSOGBEYPpZZQ7WRpZlv/06cKfJBT/dGgA4z9i9ySs8cWUoh+FGYX\nlkDB4c0CQQCK+TwfAFvrkSWorZ9Gjb6y2LZQPUufTzJNhzhK5XObCDbwyMXEM/Vs\newiyUFljlI/A9PjcrmkgrDLUMD4+og1HAkAs2t01W1uhBvEm0YH6yltCDxnThKM+\nFKEx0bQOVqN/so4LXFt83uw/tNjBkI1dA1e1qr+rm6AQICuWdwo03ApFAkBktes4\nuCTk2GHHFFM5aN0KdHviOBlGULkub9B+jjsx3UkbQxP2dITlYV/TAOFWhcGLXru+\nCPKMR93p4TAqaXtfAkA+ZZDb0mA9rtaetJlSoo6XgwI/+kqltADch9dcyqYBHwjr\nAEkzUKvmCxNAK4GEPA79FZFp30kDx+buysyeX9qY\n-----END RSA PRIVATE KEY-----",
				File:        "key.txt",
				Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
				Entropy:     5.9834013,
				Author:      "James Bond",
				Email:       "jbond@gov.co.uk",
				Date:        "2025-02-02T17:45:30Z",
				Message:     "init",
				Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
			},
			redact: 100,
			baseline: []report.Finding{
				{
					RuleID:      "private-key",
					Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
					StartLine:   1,
					EndLine:     15,
					StartColumn: 1,
					EndColumn:   30,
					Match:       "REDACTED",
					Secret:      "REDACTED",
					File:        "key.txt",
					Commit:      "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4",
					Entropy:     5.9834013,
					Author:      "James Bond",
					Email:       "jbond@gov.co.uk",
					Date:        "2025-02-02T17:45:30Z",
					Message:     "init",
					Fingerprint: "e55e00ca1690a6b5b612d28b3d9ada3fd1775ac4:key.txt:private-key:1",
				},
			},
			expect: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expect, IsNew(test.findings, test.redact, test.baseline))
		})
	}
}

func TestDetectBaselineRedact(t *testing.T) {
	// Regression test for #2355 at the scan-flow level: the baseline check
	// in DetectContext must see the raw secret, because findings are
	// redacted for output only after baseline matching. The baseline is
	// built the way a user builds one: a scan of the original secret
	// (raw here, redact 0).
	original := "github_token = \"ghp_0123456789abcdefghij0123456789abcdef\"\n"
	// Exact reversal of the secret: same length, same entropy, same
	// position — only the secret value changes, i.e. a rotation.
	rotated := "github_token = \"ghp_fedcba9876543210jihgfedcba9876543210\"\n"

	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	baseline := d.Detect(Fragment{Raw: original, FilePath: "config.py"})
	require.NotEmpty(t, baseline)

	newDetector := func(redact uint) *Detector {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = baseline
		d.Redact = redact
		return d
	}

	t.Run("unchanged secret, raw baseline, redact 100: suppressed", func(t *testing.T) {
		assert.Empty(t, newDetector(100).Detect(Fragment{Raw: original, FilePath: "config.py"}))
	})
	t.Run("rotated secret, raw baseline, redact 100: reported", func(t *testing.T) {
		findings := newDetector(100).Detect(Fragment{Raw: rotated, FilePath: "config.py"})
		require.NotEmpty(t, findings)
		var ruleIDs []string
		for _, f := range findings {
			ruleIDs = append(ruleIDs, f.RuleID)
		}
		assert.Contains(t, ruleIDs, "github-pat")
	})

	// Partial redaction: baseline written at --redact=25 holds the
	// partially masked secret; a rotation must still be reported at the
	// same redaction level, while the unchanged secret stays suppressed.
	d25, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	d25.Redact = 25
	baseline25 := d25.Detect(Fragment{Raw: original, FilePath: "config.py"})
	require.NotEmpty(t, baseline25)

	t.Run("unchanged secret, redact-25 baseline, redact 25: suppressed", func(t *testing.T) {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = baseline25
		d.Redact = 25
		assert.Empty(t, d.Detect(Fragment{Raw: original, FilePath: "config.py"}))
	})
	t.Run("rotated secret, redact-25 baseline, redact 25: reported", func(t *testing.T) {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = baseline25
		d.Redact = 25
		findings := d.Detect(Fragment{Raw: rotated, FilePath: "config.py"})
		require.NotEmpty(t, findings)
		var ruleIDs []string
		for _, f := range findings {
			ruleIDs = append(ruleIDs, f.RuleID)
		}
		assert.Contains(t, ruleIDs, "github-pat")
	})
}

func TestFileLoadBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Filename      string
		ExpectedError error
	}{
		{
			Filename:      "../testdata/baseline/baseline.csv",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.csv is not supported"),
		},
		{
			Filename:      "../testdata/baseline/baseline.sarif",
			ExpectedError: errors.New("the format of the file ../testdata/baseline/baseline.sarif is not supported"),
		},
		{
			Filename:      "../testdata/baseline/notfound.json",
			ExpectedError: errors.New("could not open ../testdata/baseline/notfound.json"),
		},
	}

	for _, test := range tests {
		_, err := LoadBaseline(test.Filename)
		assert.Equal(t, test.ExpectedError, err)
	}
}

func TestIgnoreIssuesInBaseline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		findings    []report.Finding
		baseline    []report.Finding
		expectCount int
	}{
		{
			findings: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			baseline: []report.Finding{
				{
					Author: "a",
					Commit: "5",
				},
			},
			expectCount: 0,
		},
		{
			findings: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "a",
				},
			},
			baseline: []report.Finding{
				{
					Author:      "a",
					Commit:      "5",
					Fingerprint: "b",
				},
			},
			expectCount: 0,
		},
	}

	for _, test := range tests {
		d, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		d.baseline = test.baseline
		for _, finding := range test.findings {
			d.AddFinding(finding)
		}
		assert.Len(t, d.findings, test.expectCount)
	}
}
