package detect

import (
	"bufio"
	"strings"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/report"
	"github.com/zricethezav/gitleaks/v8/sources"
)

func (d *Detector) DetectGit(gitCmd *sources.GitCmd) ([]report.Finding, error) {
	defer gitCmd.Wait()
	diffFilesCh := gitCmd.DiffFilesCh()
	errCh := gitCmd.ErrCh()

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
				if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
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
						// TODO: Get context? What if this is in the middle of a file?
						Raw:       textFragment.Raw(gitdiff.OpAdd),
						CommitSHA: commitSHA,
						FilePath:  gitdiffFile.NewName,
					}

					// Warn if the file is hosted with Git LFS. It can't be scanned (for now).
					if isLFSPointer(fragment.Raw, textFragment.OldPosition) {
						log.Warn().
							Str("commit", fragment.CommitSHA).
							Str("path", fragment.FilePath).
							Msg("File is hosted with Git LFS and cannot be scanned.")
						break
					}

					for _, finding := range d.Detect(fragment) {
						d.addFinding(augmentGitFinding(finding, textFragment, gitdiffFile))
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
	log.Info().Msgf("%d commits scanned.", len(d.commitMap))
	log.Debug().Msg("Note: this number might be smaller than expected due to commits with no additions")
	return d.findings, nil
}

var pointerKeys = []string{"version", "oid", "size"}

// isLFSPointer returns true if the fragment matches the Git LFS spec.
// https://github.com/git-lfs/git-lfs/blob/main/docs/spec.md
// https://github.com/git-lfs/git-lfs/blob/9811573f7b571bc0cafa64ffd5fdd7a6681ba722/lfs/pointer.go
func isLFSPointer(data string, oldPosition int) bool {
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
