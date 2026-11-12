package sources

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/fatih/semgroup"

	"github.com/zricethezav/gitleaks/v8/config"
)

// A text file can be classified as binary by git because of a -diff attribute
// or core.bigFileThreshold. In staged mode, its content must still be scanned.
func TestStagedScansTextFileClassifiedAsBinary(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init")
	git("config", "user.email", "test@example.com")
	git("config", "user.name", "test")

	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("secret.txt -diff\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const secret = "ghp_Zq8xR2mV7kLp4Wn9Tb3Yc6Hd1Fs5Ga0Ju2Ke"
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("token = \""+secret+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".gitattributes", "secret.txt")

	cmd, err := NewGitDiffCmd(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()

	ctx := context.Background()
	source := &Git{Cmd: cmd, Config: &config.Config{}, Sema: semgroup.NewGroup(ctx, 1)}

	var (
		mu   sync.Mutex
		seen strings.Builder
	)
	err = source.Fragments(ctx, func(fragment Fragment, err error) error {
		if err != nil {
			return err
		}
		if fragment.FilePath == "secret.txt" {
			mu.Lock()
			seen.WriteString(fragment.Raw)
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(seen.String(), secret) {
		t.Fatalf("staged secret.txt was not scanned, fragments: %q", seen.String())
	}
}
