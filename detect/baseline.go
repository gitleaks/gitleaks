package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if finding.RuleID != b.RuleID ||
			finding.Description != b.Description ||
			finding.StartLine != b.StartLine ||
			finding.EndLine != b.EndLine ||
			finding.StartColumn != b.StartColumn ||
			finding.EndColumn != b.EndColumn ||
			finding.File != b.File ||
			finding.Commit != b.Commit ||
			finding.Author != b.Author ||
			finding.Email != b.Email ||
			finding.Date != b.Date ||
			finding.Message != b.Message ||
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Entropy != b.Entropy {
			continue
		}

		if finding.Match == b.Match && finding.Secret == b.Secret {
			return false
		}

		if redact > 0 {
			// The baseline may have been written with --redact applied, so its
			// Match and Secret hold redacted values. Compare the redacted form
			// of the current finding against them: an unchanged secret still
			// matches, while a different secret on the same line is reported
			// instead of being silently swallowed. With full redaction (100),
			// both sides reduce to the same placeholder, matching previous
			// behaviour for baselines that carry no recoverable secret.
			redacted := finding
			redacted.Redact(redact)
			if redacted.Match == b.Match && redacted.Secret == b.Secret {
				return false
			}
		}
	}
	return true
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline

	}

	d.baselinePath = baselinePath
	return nil
}
