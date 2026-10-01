package sources

import (
	"context"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
)

// A failing git command must be reported as an error rather than a clean scan.
func TestGitFragmentsGitFailure(t *testing.T) {
	cmd, err := NewGitLogCmd(t.TempDir(), "")
	if err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	src := &Git{Cmd: cmd, Config: &config.Config{}}
	err = src.Fragments(context.Background(), func(Fragment, error) error { return nil })
	if err == nil {
		t.Fatal("expected an error when scanning a directory that is not a git repository")
	}
}
