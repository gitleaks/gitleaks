package detect

import (
	"bufio"
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
				for _, a := range d.Config.Allowlists {
					if ok, c := a.CommitAllowed(gitdiffFile.PatchHeader.SHA); ok {
						logging.Trace().Str("allowed-commit", c).Msg("skipping commit: global allowlist")
						continue
					}
				}
			}
			d.addCommit(commitSHA)

			d.Sema.Go(func() error {
				for _, textFragment := range gitdiffFile.TextFragments {
					if textFragment == nil {
						return nil
					}

					fragment := Fragment{
						// TODO: Get context? What if this is in the middle of a file?
						Raw:       textFragment.Raw(gitdiff.OpAdd),
						CommitSHA: commitSHA,
						FilePath:  gitdiffFile.NewName,
					}

					// Warn if the file is hosted with Git LFS. It can't be scanned (for now).
					if isLFSPointer(fragment.Raw, textFragment.OldPosition) {
						logging.Warn().
							Str("commit", fragment.CommitSHA).
							Str("path", fragment.FilePath).
							Msg("File is hosted with Git LFS and cannot be scanned.")
						break
					}

					for _, finding := range d.Detect(fragment) {
						d.AddFinding(augmentGitFinding(remote, finding, textFragment, gitdiffFile))
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

func NewRemoteInfo(platform scm.Platform, source string) *RemoteInfo {
	if platform == scm.NoPlatform {
		return &RemoteInfo{Platform: platform}
	}

	remoteUrl, err := getRemoteUrl(source)
	if err != nil {
		if strings.Contains(err.Error(), "No remote configured") {
			logging.Debug().Msg("skipping finding links: repository has no configured remote.")
			platform = scm.NoPlatform
		} else {
			logging.Error().Err(err).Msg("skipping finding links: unable to parse remote URL")
		}
		goto End
	}

	if platform == scm.UnknownPlatform {
		platform = platformFromHost(remoteUrl)
		if platform == scm.UnknownPlatform {
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
	}
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
	case "dev.azure.com", "visualstudio.com":
		return scm.AzureDevOpsPlatform
	default:
		return scm.UnknownPlatform
	}
}

var pointerKeys = []string{"version", "oid", "size"}

// isLFSPointer returns true if the fragment matches the Git LFS spec.
// https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md
// https://github.com/git-lfs/git-lfs/blob/9811573f7b571bc0cafa64ffd5fdd7a6681ba722/lfs/pointer.go
func isLFSPointer(data string, oldPosition int64) bool {
	// Only
	if oldPosition != 0 {
		return false
	}
	// "The first key is always version."
	if !strings.HasPrefix(data, "version https://git-lfs.github.com/spec/v") {
		return false
	}

	kvps := make(map[string]struct{}, len(pointerKeys))
	scanner := bufio.NewScanner(strings.NewReader(data))
	line := 0
	numKeys := len(pointerKeys)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}

		// "Each line MUST be of the format `{key} {value}\n`"
		parts := strings.SplitN(text, " ", 2)
		if len(parts) < 2 {
			return false
		}

		key := parts[0]
		// value := parts[1]

		// Extra lines could indicate a non-LFS pointer file.
		if numKeys <= line {
			return false
		}

		// Ignore extensions.
		// "ext-{order}-{name} {hash-method}:{hash-of-input-to-extension}"
		// https://github.com/git-lfs/git-lfs/blob/main/docs/extensions.md#clean
		if strings.HasPrefix(key, "ext-") {
			continue
		}

		line += 1
		kvps[key] = struct{}{}
	}

	// "The required keys are: ... version, oid, size"
	_, hasVersion := kvps["version"]
	_, hasOid := kvps["oid"]
	_, hasSize := kvps["size"]
	return hasVersion && hasOid && hasSize
}
