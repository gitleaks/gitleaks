package detect

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// githubPAT is a synthetic token matching the default github-pat rule.
const githubPAT = "ghp_Zq8xR2mV7kLp4Wn9Tb3Yc6Hd1Fs5Ga0Ju2Ke"

func initStagedRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=gitleaks-test",
			"GIT_AUTHOR_EMAIL=gitleaks-test@example.com",
			"GIT_COMMITTER_NAME=gitleaks-test",
			"GIT_COMMITTER_EMAIL=gitleaks-test@example.com",
		)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init")
	run("commit", "--allow-empty", "-m", "init")
	return dir
}

func TestStagedScanReadsGitBinaryMarkedText(t *testing.T) {
	// Regression for #2337: core.bigFileThreshold and -diff attributes make
	// `git diff --staged` emit "Binary files differ", and Fragments used to
	// skip those paths. Pre-commit then reported a clean run for a staged
	// secret. The fix reads the index blob and scans it like `gitleaks dir`.

	t.Run("bigFileThreshold", func(t *testing.T) {
		dir := initStagedRepo(t)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "secret.txt"),
			[]byte("token = \""+githubPAT+"\"\n"),
			0o644,
		))
		add := exec.Command("git", "add", "secret.txt")
		add.Dir = dir
		require.NoError(t, add.Run())
		cfg := exec.Command("git", "config", "core.bigFileThreshold", "10")
		cfg.Dir = dir
		require.NoError(t, cfg.Run())

		diff := exec.Command("git", "diff", "-U0", "--no-ext-diff", "--staged", ".")
		diff.Dir = dir
		out, err := diff.Output()
		require.NoError(t, err)
		require.Contains(t, string(out), "Binary files")

		detector, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		gitCmd, err := sources.NewGitDiffCmd(dir, true)
		require.NoError(t, err)
		findings, err := detector.DetectGit(gitCmd, NewRemoteInfo(scm.NoPlatform, dir))
		require.NoError(t, err)
		require.NotEmpty(t, findings, "expected a leak when staged text is marked binary via bigFileThreshold")
		assert.Equal(t, githubPAT, findings[0].Secret)
		assert.Equal(t, "secret.txt", findings[0].File)
	})

	t.Run("diffAttribute", func(t *testing.T) {
		dir := initStagedRepo(t)
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, "secret.txt"),
			[]byte("token = \""+githubPAT+"\"\n"),
			0o644,
		))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, ".gitattributes"),
			[]byte("secret.txt -diff\n"),
			0o644,
		))
		add := exec.Command("git", "add", "secret.txt", ".gitattributes")
		add.Dir = dir
		require.NoError(t, add.Run())

		diff := exec.Command("git", "diff", "-U0", "--no-ext-diff", "--staged", ".")
		diff.Dir = dir
		out, err := diff.Output()
		require.NoError(t, err)
		require.Contains(t, string(out), "Binary files")

		detector, err := NewDetectorDefaultConfig()
		require.NoError(t, err)
		gitCmd, err := sources.NewGitDiffCmd(dir, true)
		require.NoError(t, err)
		findings, err := detector.DetectGit(gitCmd, NewRemoteInfo(scm.NoPlatform, dir))
		require.NoError(t, err)

		var found bool
		for _, f := range findings {
			if f.File == "secret.txt" && f.Secret == githubPAT {
				found = true
				break
			}
		}
		assert.True(t, found, "expected secret.txt leak when -diff attribute marks it binary; got %#v", findings)
	})
}
