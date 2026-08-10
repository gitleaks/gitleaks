package sources

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"testing"

	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
)

// TestFragments_ErrDoesNotDropQueuedDiffFiles is a regression test for
// https://github.com/gitleaks/gitleaks/issues/2129: an error on errCh (e.g.
// git-crypt's textconv writing to stderr) must not cause Fragments to return
// before diffFilesCh has been drained, as long as the caller's yield
// callback treats the error as non-fatal (returns nil) - which is exactly
// what detect.Detector.DetectSource does.
//
// diffFilesCh and errCh are both buffered and fully loaded before Fragments
// runs, so select has both cases ready simultaneously and may pick errCh
// before any diff file is read. Which case select actually picks is up to
// the Go runtime and varies between runs, so a single iteration only
// reproduces "stderr arrives while diff files remain queued" some of the
// time (empirically caught the pre-fix bug in roughly 2 out of 3 runs).
// Repeating drives the chance of never once reproducing it to effectively
// zero, while the fixed code is expected to pass every single iteration.
func TestFragments_ErrDoesNotDropQueuedDiffFiles(t *testing.T) {
	const (
		fileCount  = 3
		iterations = 50
	)

	// Fragments' deferred cleanup unconditionally calls cmd.Wait()/String()
	// on the unexported *exec.Cmd field. Both are safe to call on a never-
	// started *exec.Cmd (Wait returns "exec: not started"; String just
	// formats Path/Args), so this doesn't need a real process - a command
	// that's never Start()ed is enough, and can be shared across iterations.
	cmd := exec.Command("gitleaks-test-never-started")

	for i := 0; i < iterations; i++ {
		diffFilesCh := make(chan *gitdiff.File, fileCount)
		for j := range fileCount {
			diffFilesCh <- &gitdiff.File{
				NewName: fmt.Sprintf("file%d.txt", j),
				TextFragments: []*gitdiff.TextFragment{{
					Lines: []gitdiff.Line{{Op: gitdiff.OpAdd, Line: fmt.Sprintf("content %d\n", j)}},
				}},
			}
		}
		close(diffFilesCh)

		errCh := make(chan error, 1)
		errCh <- errors.New("stderr is not empty")
		close(errCh)

		g := &Git{
			Cmd: &GitCmd{
				cmd:         cmd,
				diffFilesCh: diffFilesCh,
				errCh:       errCh,
			},
			Config: &config.Config{},
			Sema:   semgroup.NewGroup(context.Background(), fileCount),
		}

		var (
			mu      sync.Mutex
			yielded []string
		)
		err := g.Fragments(context.Background(), func(fragment Fragment, err error) error {
			if err != nil {
				return nil
			}
			mu.Lock()
			yielded = append(yielded, fragment.Raw)
			mu.Unlock()
			return nil
		})
		require.NoError(t, err)

		assert.ElementsMatchf(t, []string{"content 0\n", "content 1\n", "content 2\n"}, yielded, "iteration %d", i)
	}
}

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
