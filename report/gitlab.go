package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// GitlabCodeQualityReporter emits findings in the
// GitLab Code Quality JSON format so they can be picked up as a Code Quality
// MR widget artifact (artifacts:reports:codequality in .gitlab-ci.yml).
//
// Spec: https://docs.gitlab.com/ee/ci/testing/code_quality.html#code-quality-report-format
type GitlabCodeQualityReporter struct{}

var _ Reporter = (*GitlabCodeQualityReporter)(nil)

func (r *GitlabCodeQualityReporter) Write(w io.WriteCloser, findings []Finding) error {
	issues := make([]gitlabCQIssue, 0, len(findings))
	for _, f := range findings {
		issues = append(issues, toGitlabCQIssue(f))
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", " ")
	return encoder.Encode(issues)
}

func toGitlabCQIssue(f Finding) gitlabCQIssue {
	path := f.File
	if f.SymlinkFile != "" {
		path = f.SymlinkFile
	}

	return gitlabCQIssue{
		Type:        "issue",
		CheckName:   f.RuleID,
		Description: gitlabCQDescription(f),
		Fingerprint: gitlabCQFingerprint(f),
		Severity:    "critical",
		Categories:  []string{"Security"},
		EngineName:  driver,
		Location: gitlabCQLocation{
			Path: path,
			Lines: gitlabCQLines{
				Begin: f.StartLine,
			},
		},
	}
}

func gitlabCQDescription(f Finding) string {
	if f.Description == "" {
		return fmt.Sprintf("%s has detected a hardcoded secret in %s.", f.RuleID, f.File)
	}
	return fmt.Sprintf("%s: %s", f.RuleID, f.Description)
}

// gitlabCQFingerprint returns a stable per-finding identifier used by GitLab
// to deduplicate Code Quality issues across pipeline runs. We prefer the
// gitleaks Fingerprint when present (already commit+file+line+ruleid based);
// otherwise we fall back to a hash of the fields that uniquely describe the
// finding so callers running outside a git repo still get a stable id.
func gitlabCQFingerprint(f Finding) string {
	if f.Fingerprint != "" {
		sum := sha256.Sum256([]byte(f.Fingerprint))
		return hex.EncodeToString(sum[:])
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%d|%d|%s",
		f.RuleID, f.File, f.Commit, f.StartLine, f.StartColumn, f.Secret)
	return hex.EncodeToString(h.Sum(nil))
}

type gitlabCQIssue struct {
	Type        string           `json:"type"`
	CheckName   string           `json:"check_name"`
	Description string           `json:"description"`
	Fingerprint string           `json:"fingerprint"`
	Severity    string           `json:"severity"`
	Categories  []string         `json:"categories,omitempty"`
	EngineName  string           `json:"engine_name,omitempty"`
	Location    gitlabCQLocation `json:"location"`
}

type gitlabCQLocation struct {
	Path  string        `json:"path"`
	Lines gitlabCQLines `json:"lines"`
}

type gitlabCQLines struct {
	Begin int `json:"begin"`
}
