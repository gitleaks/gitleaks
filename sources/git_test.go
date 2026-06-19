package sources

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zricethezav/gitleaks/v8/config"
)

func TestIsCommitAllowed(t *testing.T) {
	tests := map[string]struct {
		allowlists  []*config.Allowlist
		sha         string
		wantAllowed bool
		wantCommit  string
	}{
		"no allowlists": {
			allowlists:  nil,
			sha:         "commitA",
			wantAllowed: false,
		},
		"single allowlist matches": {
			allowlists:  []*config.Allowlist{{Commits: []string{"commitA"}}},
			sha:         "commitA",
			wantAllowed: true,
			wantCommit:  "commitA",
		},
		"single allowlist does not match": {
			allowlists:  []*config.Allowlist{{Commits: []string{"commitB"}}},
			sha:         "commitA",
			wantAllowed: false,
		},
		"empty sha is never allowed": {
			allowlists:  []*config.Allowlist{{Commits: []string{"commitA"}}},
			sha:         "",
			wantAllowed: false,
		},
		// The original bug: the allowed commit lived in a later allowlist and the
		// misscoped continue let it fall through to be scanned anyway. Match on a
		// non-first entry guards against that regression.
		"match in a later allowlist": {
			allowlists: []*config.Allowlist{
				{Commits: []string{"commitB"}},
				{Commits: []string{"commitA"}},
			},
			sha:         "commitA",
			wantAllowed: true,
			wantCommit:  "commitA",
		},
		// Overlapping allowlists: both cover the commit. We stop at the first
		// match and never scan, regardless of how many entries match.
		"overlapping allowlists both match": {
			allowlists: []*config.Allowlist{
				{Commits: []string{"commitA"}},
				{Commits: []string{"commitA"}},
			},
			sha:         "commitA",
			wantAllowed: true,
			wantCommit:  "commitA",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			gotAllowed, gotCommit := isCommitAllowed(tt.allowlists, tt.sha)
			assert.Equal(t, tt.wantAllowed, gotAllowed)
			if tt.wantAllowed {
				assert.Equal(t, tt.wantCommit, gotCommit)
			}
		})
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
