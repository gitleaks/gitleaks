package sources

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fatih/semgroup"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// TODO: commenting out this test for now because it's flaky. Alternatives to consider to get this working:
// -- use `git stash` instead of `restore()`

// const repoBasePath = "../../testdata/repos/"

// const expectPath = "../../testdata/expected/"

// func TestGitLog(t *testing.T) {
// 	tests := []struct {
// 		source   string
// 		logOpts  string
// 		expected string
// 	}{
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small.txt"),
// 		},
// 		{
// 			source:   filepath.Join(repoBasePath, "small"),
// 			expected: filepath.Join(expectPath, "git", "small-branch-foo.txt"),
// 			logOpts:  "--all foo...",
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		files, err := git.GitLog(tt.source, tt.logOpts)
// 		if err != nil {
// 			t.Error(err)
// 		}

// 		var diffSb strings.Builder
// 		for f := range files {
// 			for _, tf := range f.TextFragments {
// 				diffSb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 		}

// 		expectedBytes, err := os.ReadFile(tt.expected)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		expected := string(expectedBytes)
// 		if expected != diffSb.String() {
// 			// write string builder to .got file using os.Create
// 			err = os.WriteFile(strings.Replace(tt.expected, ".txt", ".got.txt", 1), []byte(diffSb.String()), 0644)
// 			if err != nil {
// 				t.Error(err)
// 			}
// 			t.Error("expected: ", expected, "got: ", diffSb.String())
// 		}
// 	}
// }

// func TestGitDiff(t *testing.T) {
// 	tests := []struct {
// 		source    string
// 		expected  string
// 		additions string
// 		target    string
// 	}{
// 		{
// 			source:    filepath.Join(repoBasePath, "small"),
// 			expected:  "this line is added\nand another one",
// 			additions: "this line is added\nand another one",
// 			target:    filepath.Join(repoBasePath, "small", "main.go"),
// 		},
// 	}

// 	err := moveDotGit("dotGit", ".git")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer func() {
// 		if err = moveDotGit(".git", "dotGit"); err != nil {
// 			t.Fatal(err)
// 		}
// 	}()

// 	for _, tt := range tests {
// 		noChanges, err := os.ReadFile(tt.target)
// 		if err != nil {
// 			t.Error(err)
// 		}
// 		err = os.WriteFile(tt.target, []byte(tt.additions), 0644)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		files, err := git.GitDiff(tt.source, false)
// 		if err != nil {
// 			restore(tt.target, noChanges, t)
// 			t.Error(err)
// 		}

// 		for f := range files {
// 			sb := strings.Builder{}
// 			for _, tf := range f.TextFragments {
// 				sb.WriteString(tf.Raw(gitdiff.OpAdd))
// 			}
// 			if sb.String() != tt.expected {
// 				restore(tt.target, noChanges, t)
// 				t.Error("expected: ", tt.expected, "got: ", sb.String())
// 			}
// 		}
// 		restore(tt.target, noChanges, t)
// 	}
// }

// func restore(path string, data []byte, t *testing.T) {
// 	err := os.WriteFile(path, data, 0644)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func moveDotGit(from, to string) error {
// 	repoDirs, err := os.ReadDir("../../testdata/repos")
// 	if err != nil {
// 		return err
// 	}
// 	for _, dir := range repoDirs {
// 		if to == ".git" {
// 			_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), "dotGit"))
// 			if os.IsNotExist(err) {
// 				// dont want to delete the only copy of .git accidentally
// 				continue
// 			}
// 			os.RemoveAll(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), ".git"))
// 		}
// 		if !dir.IsDir() {
// 			continue
// 		}
// 		_, err := os.Stat(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from))
// 		if os.IsNotExist(err) {
// 			continue
// 		}

// 		err = os.Rename(fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), from),
// 			fmt.Sprintf("%s/%s/%s", repoBasePath, dir.Name(), to))
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }

// The diff below is the one reported in
// https://github.com/gitleaks/gitleaks/issues/1338: `git` emitted a hunk header
// whose old-file line count had overflowed, and `gitdiff.Parse` reacted the only
// way its streaming API can, by dropping the error and closing its channel. That
// leaves gitleaks with a diff it stopped reading and no way to tell a truncated
// scan from a clean one.
const (
	wellFormedDiff = `commit 6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b
Author: Test <test@example.com>
Date:   Sun Feb 11 21:44:04 2024 +0000

    a commit

diff --git a/first.txt b/first.txt
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/first.txt
@@ -0,0 +1 @@
+first
diff --git a/second.txt b/second.txt
new file mode 100644
index 0000000..2222222
--- /dev/null
+++ b/second.txt
@@ -0,0 +1 @@
+second
`

	unparseableDiff = `commit 6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b
Author: Test <test@example.com>
Date:   Sun Feb 11 21:44:04 2024 +0000

    a commit

diff --git a/first.txt b/first.txt
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/first.txt
@@ -0,0 +1 @@
+first
diff --git a/bad.txt b/bad.txt
index 2222222..3333333 100644
--- a/bad.txt
+++ b/bad.txt
@@ -231,18446744073709551615 +231,1 @@
+bad
diff --git a/second.txt b/second.txt
new file mode 100644
index 0000000..4444444
--- /dev/null
+++ b/second.txt
@@ -0,0 +1 @@
+second
`
)

// gitCmdFromDiff returns a GitCmd whose `git` process writes diff to stdout,
// padded with trailing comment lines so that it does not fit in the OS pipe
// buffer. The bytes are stashed in a throwaway repository and replayed with
// `git cat-file`, which keeps the test on real git without needing a repository
// that can actually produce the diff.
func gitCmdFromDiff(t *testing.T, diff string, pad int) *GitCmd {
	t.Helper()

	repo := t.TempDir()
	require.NoError(t, exec.Command("git", "init", "--quiet", repo).Run())

	payload := diff + strings.Repeat("# padding to fill the pipe buffer\n", pad)
	hashObject := exec.Command("git", "-C", repo, "hash-object", "-w", "--stdin")
	hashObject.Stdin = strings.NewReader(payload)
	out, err := hashObject.Output()
	require.NoError(t, err)

	cmd := exec.Command("git", "-C", repo, "cat-file", "blob", string(bytes.TrimSpace(out)))
	gitCmd, err := newGitCmd(cmd, repo)
	require.NoError(t, err)
	t.Cleanup(func() {
		if gitCmd.cmd.Process != nil {
			_ = gitCmd.cmd.Process.Kill()
		}
	})
	return gitCmd
}

func TestGitCmdUnparsedBytes(t *testing.T) {
	cases := []struct {
		name          string
		diff          string
		wantFiles     []string
		wantTruncated bool
	}{
		{
			name:      "diff read to the end",
			diff:      wellFormedDiff,
			wantFiles: []string{"first.txt", "second.txt"},
		},
		{
			// second.txt sits behind the bad hunk header, so it is never scanned.
			name:          "diff abandoned on a bad hunk header",
			diff:          unparseableDiff,
			wantFiles:     []string{"first.txt"},
			wantTruncated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gitCmd := gitCmdFromDiff(t, tc.diff, 0)

			var files []string
			for f := range gitCmd.DiffFilesCh() {
				files = append(files, f.NewName)
			}
			require.Equal(t, tc.wantFiles, files)

			unparsed := gitCmd.UnparsedBytes()
			if tc.wantTruncated {
				require.Greater(t, unparsed, int64(0), "leftover output is the only sign that the scan stopped early")
			} else {
				require.Zero(t, unparsed, "a diff that parsed to the end must not look truncated")
			}
			require.NoError(t, gitCmd.Wait())
		})
	}
}

// TestGitFragmentsUnparseableDiff covers gitleaks#1338: when the parser gives up
// partway through, whatever git has not written yet stays in the pipe. Nothing
// drains it, so git never exits, its stderr never reaches EOF, and Fragments
// waits on a channel that will never close.
func TestGitFragmentsUnparseableDiff(t *testing.T) {
	// Enough padding to overflow the pipe buffer, which is what makes git block.
	gitCmd := gitCmdFromDiff(t, unparseableDiff, 32*1024)

	source := &Git{
		Cmd:    gitCmd,
		Config: &config.Config{},
		Remote: &RemoteInfo{},
		Sema:   semgroup.NewGroup(context.Background(), 4),
	}

	var (
		mu       sync.Mutex
		scanned  []string
		yielded  []error
		finished = make(chan error, 1)
	)
	go func() {
		finished <- source.Fragments(context.Background(), func(f Fragment, err error) error {
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				yielded = append(yielded, err)
			} else {
				scanned = append(scanned, f.FilePath)
			}
			return nil
		})
	}()

	select {
	case err := <-finished:
		require.NoError(t, err)
	case <-time.After(30 * time.Second):
		t.Fatal("Fragments did not return: git is still blocked writing a diff nobody is reading")
	}

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"first.txt"}, scanned)
	require.Len(t, yielded, 1, "an unfinished scan has to be reported, not passed off as a clean one")
	require.ErrorContains(t, yielded[0], "diff parsing stopped early")
	require.ErrorContains(t, yielded[0], "results are incomplete")
}
