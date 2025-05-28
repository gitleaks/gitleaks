package sources

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/zricethezav/gitleaks/v8/logging"
)

var quotedOptPattern = regexp.MustCompile(`^(?:"[^"]+"|'[^']+')$`)

// GitCmd helps to work with Git's output.
type GitCmd struct {
	repoPath    string
	cmd         *exec.Cmd
	diffFilesCh <-chan *gitdiff.File
	errCh       <-chan error
}

type GitInfo struct {
	Source  string
	Commit  string
	Link    string
	Author  string
	Email   string
	Date    string
	Message string
}

// NewGitLogCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
func NewGitLogCmd(source string, logOpts string) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	if logOpts != "" {
		args := []string{"-C", sourceClean, "log", "-p", "-U0"}

		// Ensure that the user-provided |logOpts| aren't wrapped in quotes.
		// https://github.com/gitleaks/gitleaks/issues/1153
		userArgs := strings.Split(logOpts, " ")
		var quotedOpts []string
		for _, element := range userArgs {
			if quotedOptPattern.MatchString(element) {
				quotedOpts = append(quotedOpts, element)
			}
		}
		if len(quotedOpts) > 0 {
			logging.Warn().Msgf("the following `--log-opts` values may not work as expected: %v\n\tsee https://github.com/gitleaks/gitleaks/issues/1153 for more information", quotedOpts)
		}

		args = append(args, userArgs...)
		cmd = exec.Command("git", args...)
	} else {
		cmd = exec.Command("git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all")
	}

	logging.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		repoPath:    sourceClean,
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
	}, nil
}

// NewGitDiffCmd returns `*DiffFilesCmd` with two channels: `<-chan *gitdiff.File` and `<-chan error`.
// Caller should read everything from channels until receiving a signal about their closure and call
// the `func (*DiffFilesCmd) Wait()` error in order to release resources.
func NewGitDiffCmd(source string, staged bool) (*GitCmd, error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff", ".")
	if staged {
		cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0", "--no-ext-diff",
			"--staged", ".")
	}
	logging.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)

	gitdiffFiles, err := gitdiff.Parse(stdout)
	if err != nil {
		return nil, err
	}

	return &GitCmd{
		repoPath:    sourceClean,
		cmd:         cmd,
		diffFilesCh: gitdiffFiles,
		errCh:       errCh,
	}, nil
}

// CheckoutBlob writes the contents of the blob at commit:filepath into a temp file
// and returns its path.
func (g *GitCmd) CheckoutBlob(commit, filepathInRepo string) (string, error) {
	// Create a temp file with the same extension as the blob, if possible
	ext := filepath.Ext(filepathInRepo)
	// tmpDir, err := os.MkdirTemp("gitleaks", "archive-*")
	tmpFile, err := os.CreateTemp("", "gitleaks-blob-*"+ext)
	if err != nil {
		return "", fmt.Errorf("creating temp file for blob: %w", err)
	}
	tmpFilePath := tmpFile.Name()
	tmpFile.Close()

	// git show <commit>:<path>
	gitArgs := []string{"-C", g.repoPath, "show", fmt.Sprintf("%s:%s", commit, filepathInRepo)}
	cmd := exec.Command("git", gitArgs...)
	cmd.Stdout, err = os.OpenFile(tmpFilePath, os.O_WRONLY, 0o644)
	if err != nil {
		os.Remove(tmpFilePath)
		return "", fmt.Errorf("opening temp file for write: %w", err)
	}

	if err := cmd.Run(); err != nil {
		os.Remove(tmpFilePath)
		return "", fmt.Errorf("git show failed: %w", err)
	}

	return tmpFilePath, nil
}

// DiffFilesCh returns a channel with *gitdiff.File.
func (c *GitCmd) DiffFilesCh() <-chan *gitdiff.File {
	return c.diffFilesCh
}

// ErrCh returns a channel that could produce an error if there is something in stderr.
func (c *GitCmd) ErrCh() <-chan error {
	return c.errCh
}

// Wait waits for the command to exit and waits for any copying to
// stdin or copying from stdout or stderr to complete.
//
// Wait also closes underlying stdout and stderr.
func (c *GitCmd) Wait() (err error) {
	return c.cmd.Wait()
}

// listenForStdErr listens for stderr output from git, prints it to stdout,
// sends to errCh and closes it.
func listenForStdErr(stderr io.ReadCloser, errCh chan<- error) {
	defer close(errCh)

	var errEncountered bool

	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		// if git throws one of the following errors:
		//
		//  exhaustive rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//	inexact rename detection was skipped due to too many files.
		//  you may want to set your diff.renameLimit variable to at least
		//  (some large number) and retry the command.
		//
		//  Auto packing the repository in background for optimum performance.
		//  See "git help gc" for manual housekeeping.
		//
		// we skip exiting the program as git log -p/git diff will continue
		// to send data to stdout and finish executing. This next bit of
		// code prevents gitleaks from stopping mid scan if this error is
		// encountered
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") ||
			strings.Contains(scanner.Text(),
				"See \"git help gc\" for manual housekeeping") ||
			strings.Contains(scanner.Text(),
				"Auto packing the repository in background for optimum performance") {
			logging.Warn().Msg(scanner.Text())
		} else {
			logging.Error().Msgf("[git] %s", scanner.Text())
			errEncountered = true
		}
	}

	if errEncountered {
		errCh <- errors.New("stderr is not empty")
		return
	}
}
