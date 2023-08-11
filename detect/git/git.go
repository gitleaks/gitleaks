package git

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// GitLog returns a channel of gitdiff.File objects from the
// git log -p command for the given source.
var quotedOptPattern = regexp.MustCompile(`^(?:"[^"]+"|'[^']+')$`)

func GitLog(source string, logOpts string) (gitdiffFiles <-chan *gitdiff.File, err error) {
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
			log.Warn().Msgf("the following `--log-opts` values may not work as expected: %v\n\tsee https://github.com/gitleaks/gitleaks/issues/1153 for more information", quotedOpts)
		}

		args = append(args, userArgs...)
		cmd = exec.Command("git", args...)
	} else {
		cmd = exec.Command("git", "-C", sourceClean, "log", "-p", "-U0",
			"--full-history", "--all")
	}

	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	defer stderr.Close()

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)
	defer func() {
		stderrErr := <-errCh
		if err != nil {
			if stderrErr != nil {
				log.Error().Err(err).Msgf("stderr not empty")
			}
			return
		}
		err = stderrErr
	}()

	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	defer cmd.Wait()

	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, stdout)
	if err != nil {
		return nil, err
	}

	gitdiffFiles, err = gitdiff.Parse(buf)
	if err != nil {
		return nil, err
	}

	return gitdiffFiles, nil
}

// GitDiff returns a channel of gitdiff.File objects from
// the git diff command for the given source.
func GitDiff(source string, staged bool) (gitdiffFiles <-chan *gitdiff.File, err error) {
	sourceClean := filepath.Clean(source)
	var cmd *exec.Cmd
	cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0", ".")
	if staged {
		cmd = exec.Command("git", "-C", sourceClean, "diff", "-U0",
			"--staged", ".")
	}
	log.Debug().Msgf("executing: %s", cmd.String())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	defer stderr.Close()

	errCh := make(chan error)
	go listenForStdErr(stderr, errCh)
	defer func() {
		stderrErr := <-errCh
		if err != nil {
			if stderrErr != nil {
				log.Error().Err(err).Msgf("stderr not empty")
			}
			return
		}
		err = stderrErr
	}()

	err = cmd.Start()
	if err != nil {
		return nil, err
	}
	defer cmd.Wait()

	buf := bytes.NewBuffer(nil)
	_, err = io.Copy(buf, stdout)
	if err != nil {
		return nil, err
	}

	gitdiffFiles, err = gitdiff.Parse(buf)
	if err != nil {
		return nil, err
	}

	return gitdiffFiles, nil
}

// listenForStdErr listens for stderr output from git and prints it to stdout
// then exits with exit code 1
func listenForStdErr(stderr io.ReadCloser, errCh chan error) {
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
		// we skip exiting the program as git log -p/git diff will continue
		// to send data to stdout and finish executing. This next bit of
		// code prevents gitleaks from stopping mid scan if this error is
		// encountered
		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") {
			log.Warn().Msg(scanner.Text())
		} else {
			log.Error().Msgf("[git] %s", scanner.Text())
			errEncountered = true
		}
	}

	if errEncountered {
		errCh <- errors.New("stderr is not empty")
		return
	}

	errCh <- nil
}
