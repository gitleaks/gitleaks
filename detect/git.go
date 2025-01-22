package detect

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"

	"github.com/zricethezav/gitleaks/v8/cmd/scm"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func (d *Detector) DetectGit(cmd *sources.GitCmd, remote *RemoteInfo) ([]report.Finding, error) {
	defer cmd.Wait()
	var (
		diffFilesCh = cmd.DiffFilesCh()
		errCh       = cmd.ErrCh()
	)

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			}

			// skip binary files
			if gitdiffFile.IsBinary || gitdiffFile.IsDelete {
				continue
			}

			// Check if commit is allowed
			commitSHA := ""
			if gitdiffFile.PatchHeader != nil {
				commitSHA = gitdiffFile.PatchHeader.SHA
				if ok, c := d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA); ok {
					logging.Trace().Str("allowed-commit", c).Msg("skipping commit: global allowlist")
					continue
				}
			}
			d.addCommit(commitSHA)

			d.Sema.Go(func() error {
				for _, textFragment := range gitdiffFile.TextFragments {
					if textFragment == nil {
						return nil
					}

					fragment := Fragment{
						Raw:       textFragment.Raw(gitdiff.OpAdd),
						CommitSHA: commitSHA,
						FilePath:  gitdiffFile.NewName,
					}

					for _, finding := range d.Detect(fragment) {
						d.addFinding(augmentGitFinding(remote.Platform, remote.Url, finding, textFragment, gitdiffFile))
					}
				}
				return nil
			})
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			return d.findings, err
		}
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}
	logging.Info().Msgf("%d commits scanned.", len(d.commitMap))
	logging.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	return d.findings, nil
}

type RemoteInfo struct {
	Platform scm.Platform
	Url      string
}

func NewRemoteInfo(platform scm.Platform, source string) (*RemoteInfo, error) {
	remoteUrl, err := getRemoteUrl(source)
	if err != nil {
		if strings.Contains(err.Error(), "No remote configured") {
			logging.Debug().Msg("skipping finding links: repository has no configured remote.")
			platform = scm.NoPlatform
			goto End
		}
		return nil, fmt.Errorf("unable to get remote URL: %w", err)
	}

	if platform == scm.NoPlatform {
		platform = platformFromHost(remoteUrl)
		if platform == scm.NoPlatform {
			logging.Info().
				Str("host", remoteUrl.Hostname()).
				Msg("Unknown SCM platform. Use --platform to include links in findings.")
		} else {
			logging.Debug().
				Str("host", remoteUrl.Hostname()).
				Str("platform", platform.String()).
				Msg("SCM platform parsed from host")
		}
	}

End:
	var rUrl string
	if remoteUrl != nil {
		rUrl = remoteUrl.String()
	}
	return &RemoteInfo{
		Platform: platform,
		Url:      rUrl,
	}, nil
}

var sshUrlpat = regexp.MustCompile(`^git@([a-zA-Z0-9.-]+):([\w/.-]+?)(?:\.git)?$`)

func getRemoteUrl(source string) (*url.URL, error) {
	// This will return the first remote — typically, "origin".
	cmd := exec.Command("git", "ls-remote", "--quiet", "--get-url")
	if source != "." {
		cmd.Dir = source
	}

	stdout, err := cmd.Output()
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return nil, fmt.Errorf("command failed (%d): %w, stderr: %s", exitError.ExitCode(), err, string(bytes.TrimSpace(exitError.Stderr)))
		}
		return nil, err
	}

	remoteUrl := string(bytes.TrimSpace(stdout))
	if matches := sshUrlpat.FindStringSubmatch(remoteUrl); matches != nil {
		remoteUrl = fmt.Sprintf("https://%s/%s", matches[1], matches[2])
	}
	remoteUrl = strings.TrimSuffix(remoteUrl, ".git")

	parsedUrl, err := url.Parse(remoteUrl)
	if err != nil {
		return nil, fmt.Errorf("unable to parse remote URL: %w", err)
	}

	// Remove any user info.
	parsedUrl.User = nil
	return parsedUrl, nil
}

func platformFromHost(u *url.URL) scm.Platform {
	switch strings.ToLower(u.Hostname()) {
	case "github.com":
		return scm.GitHubPlatform
	case "gitlab.com":
		return scm.GitLabPlatform
	default:
		return scm.NoPlatform
	}
}
