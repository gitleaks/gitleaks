package detect

import (
	"fmt"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
	"io"
)

func (d *Detector) DetectGit(gitCmd *sources.GitCmd) ([]report.Finding, error) {
	defer gitCmd.Wait()
	diffFilesCh := gitCmd.DiffFilesCh()
	errCh := gitCmd.ErrCh()

	// Open the local git repository
	// TODO: make this lazy?
	// TODO: Test this with bare repsoitories
	var (
		sourcePath = gitCmd.GetRepoPath()
		repo       *git.Repository
		err        error
	)
	//if strings.HasSuffix(sourcePath, ".git") {
	//	repo, err = git.PlainOpenWithOptions(gitCmd.GetRepoPath())
	//} else {
	repo, err = git.PlainOpen(sourcePath)
	//}

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
				if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
					continue
				}
			}
			d.addCommit(commitSHA)

			if gitdiffFile.IsBinary {
				if !d.ScanBinaryFiles {
					log.Trace().
						Str("commit", commitSHA).
						Str("path", gitdiffFile.NewName).
						Str("reason", "binary scanning not enabled").
						Msg("Skipping binary file.")
					continue
				}

				// Checkout and scan binary files.
				// TODO: Should binary files have their own semaphore?
				if err := d.detectBinary(repo, commitSHA, gitdiffFile); err != nil {
					log.Error().Err(err).
						Str("commit", commitSHA).
						Str("path", gitdiffFile.NewName).
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
							d.addFinding(augmentGitFinding(finding, gitdiffFile, textFragment))
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
		log.Info().Msgf("%s: %d", k, v.Load())
	}

	if err := d.Sema.Wait(); err != nil {
		return d.findings, err
	}
	log.Info().Msgf("%d commits scanned.", len(d.commitMap))
	log.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	return d.findings, nil
}

func (d *Detector) detectBinary(repo *git.Repository, commitHash string, gitdiffFile *gitdiff.File) error {
	filePath := gitdiffFile.NewName
	logger := log.With().Str("commit", commitHash).Str("path", filePath).Logger()
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
		_ = reader.Close()
	}(reader)

	if err = handleFile(filePath, reader); err != nil {
		log.Error().Err(err).
			Str("path", filePath).
			Msgf("Failed to identify file")
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
				d.addFinding(augmentGitFinding(finding, gitdiffFile, nil))
			}
		}

		if err != nil {
			if err != io.EOF {
				return err
			}
			break
		}
	}

	//// Replace the previous streaming code with this:
	//var buf bytes.Buffer
	//if _, err = io.Copy(&buf, reader); err != nil {
	//	return fmt.Errorf("failed to read file content: %w", err)
	//}

	//// Create a temporary directory
	//tempDir, err := os.MkdirTemp("", "gitleaks-")
	//if err != nil {
	//	return fmt.Errorf("failed to create temporary directory: %w", err)
	//}
	//defer func(path string) {
	//	_ = os.RemoveAll(path)
	//}(tempDir)
	//
	//// Create the destination file in the temporary directory
	//destFilePath := filepath.Join(tempDir, filepath.Base(filePath))
	//destFile, err := os.Create(destFilePath)
	//if err != nil {
	//	return fmt.Errorf("failed to create destination file: %w", err)
	//}
	//defer func(destFile *os.File) {
	//	_ = destFile.Close()
	//}(destFile)
	//
	//// Copy the file content to the temporary file
	//_, err = io.Copy(destFile, reader)
	//if err != nil {
	//	return fmt.Errorf("failed to copy file content: %w", err)
	//}
	//
	//fmt.Printf("File copied to: %s\n", destFile.Name())

	return nil
}
