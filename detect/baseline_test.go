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
		"not new - redacted, everything else matches": {
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
			expect: false,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, test.expect, IsNew(test.findings, test.redact, test.baseline))
		})
	}
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
