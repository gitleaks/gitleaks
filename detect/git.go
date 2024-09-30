package detect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/mholt/archives"

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

	// Open the local git repository
	// TODO: make this lazy?
	// TODO: Test this with bare repsoitories
	var (
		sourcePath = cmd.GetRepoPath()
		repo       *git.Repository
		err        error
	)
	// if strings.HasSuffix(sourcePath, ".git") {
	//	repo, err = git.PlainOpenWithOptions(gitCmd.GetRepoPath())
	// } else {
	repo, err = git.PlainOpen(sourcePath)
	// }

	if err != nil {
		return nil, fmt.Errorf("failed to open local repository: %w", err)

	}

	// loop to range over both DiffFiles (stdout) and ErrCh (stderr)
	for diffFilesCh != nil || errCh != nil {
		select {
		case gitdiffFile, open := <-diffFilesCh:
			if !open {
				diffFilesCh = nil
				break
			} else if gitdiffFile.IsDelete {
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

			logger := logging.With().Str("commit", commitSHA).Str("path", gitdiffFile.NewName).Logger()
			if gitdiffFile.IsBinary {
				if !d.ScanBinaryFiles {
					logger.Trace().
						Str("reason", "binary scanning not enabled").
						Msg("Skipping binary file.")
					continue
				}

				// Checkout and scan binary files.
				// TODO: Should binary files have their own semaphore?
				if err := d.detectBinary(repo, remote, commitSHA, gitdiffFile); err != nil {
					logger.Error().
						Err(err).
						Msg("Failed to scan binary file.")
				}
			} else {
				// Scan text diffs.
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
							d.AddFinding(augmentGitFinding(remote, finding, gitdiffFile, textFragment))
						}
					}
					return nil
				})
			}
		case err, open := <-errCh:
			if !open {
				errCh = nil
				break
			}

			return d.findings, err
		}
	}

	// TODO: Remove this.
	for k, v := range count {
		logging.Info().Msgf("%s: %d", k, v.Load())
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

func (d *Detector) detectBinary(repo *git.Repository, remote *RemoteInfo, commitHash string, gitdiffFile *gitdiff.File) error {
	filePath := gitdiffFile.NewName
	logger := logging.With().Str("commit", commitHash).Str("path", filePath).Logger()
	// Check if the file is worth scanning.
	if ok, reason := shouldScanBinaryFile(filePath); !ok {
		logger.Trace().Str("reason", reason).Msg("Skipping binary file.")
		return nil
	}
	logger.Trace().Msg("Scanning binary file.")

	// Read the file.
	commit, err := repo.CommitObject(plumbing.NewHash(commitHash))
	if err != nil {
		return fmt.Errorf("error getting commit object: %w", err)
	}

	// Get the tree associated with this commit
	tree, err := commit.Tree()
	if err != nil {
		return fmt.Errorf("error getting commit tree: %w", err)
	}

	// Get the specific file in the commit's tree
	file, err := tree.File(filePath)
	if err != nil {
		return fmt.Errorf("error getting file in tree: %w", err)
	}

	// Check if the file is a reasonable size.
	if d.MaxTargetMegaBytes > 0 && file.Size > d.MaxTargetMegaBytes {
		logger.Debug().
			Int64("size", file.Size).
			Int64("limit", d.MaxTargetMegaBytes).
			Str("reason", "size").
			Msg("Skipping binary file.")
		return nil
	}

	// Open the file content as a reader
	reader, err := file.Reader()
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}
	defer func(reader io.ReadCloser) {
		_, _ = io.Copy(io.Discard, reader)
		_ = reader.Close()
	}(reader)

	ctx := logger.WithContext(
		context.WithValue(context.Background(), "commit", commitHash))
	if findings, err := d.handleFile(ctx, filePath, reader, true); err != nil {
		if !errors.Is(err, archives.NoMatch) {
			logger.Error().Err(err).
				Str("path", filePath).
				Msgf("Failed to identify file")
		}
	} else {
		for _, finding := range findings {
			d.AddFinding(augmentGitFinding(remote, finding, gitdiffFile, nil))
		}
		return nil
	}

	// Scan the reader.
	// TODO: Deduplicate logic between here, directory.go, and reader.go?
	var buf = make([]byte, 0, chunkSize)
	for {
		n, err := reader.Read(buf[:cap(buf)])

		// "Callers should always process the n > 0 bytes returned before considering the error err."
		// https://pkg.go.dev/io#Reader
		if n > 0 {
			buf = buf[:n]
			fragment := Fragment{
				Raw:       string(buf),
				CommitSHA: commitHash,
				FilePath:  filePath,
			}
			for _, finding := range d.Detect(fragment) {
				d.AddFinding(augmentGitFinding(remote, finding, gitdiffFile, nil))
			}
		}

		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}

	// // Replace the previous streaming code with this:
	// var buf bytes.Buffer
	// if _, err = io.Copy(&buf, reader); err != nil {
	//	return fmt.Errorf("failed to read file content: %w", err)
	// }

	// // Create a temporary directory
	// tempDir, err := os.MkdirTemp("", "gitleaks-")
	// if err != nil {
	//	return fmt.Errorf("failed to create temporary directory: %w", err)
	// }
	// defer func(path string) {
	//	_ = os.RemoveAll(path)
	// }(tempDir)
	//
	// // Create the destination file in the temporary directory
	// destFilePath := filepath.Join(tempDir, filepath.Base(filePath))
	// destFile, err := os.Create(destFilePath)
	// if err != nil {
	//	return fmt.Errorf("failed to create destination file: %w", err)
	// }
	// defer func(destFile *os.File) {
	//	_ = destFile.Close()
	// }(destFile)
	//
	// // Copy the file content to the temporary file
	// _, err = io.Copy(destFile, reader)
	// if err != nil {
	//	return fmt.Errorf("failed to copy file content: %w", err)
	// }
	//
	// fmt.Printf("File copied to: %s\n", destFile.Name())

	return nil
}
