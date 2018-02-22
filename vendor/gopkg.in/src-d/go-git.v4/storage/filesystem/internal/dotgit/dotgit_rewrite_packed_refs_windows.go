// +build windows,!norwfs

package dotgit

import (
	"io"
	"os"

	"gopkg.in/src-d/go-billy.v4"
)

const openAndLockPackedRefsMode = os.O_RDWR

func (d *DotGit) rewritePackedRefsWhileLocked(
	tmp billy.File, pr billy.File) error {
	// If we aren't using the bare Windows filesystem as the storage
	// layer, we might be able to get away with a rename over a locked
	// file.
	err := d.fs.Rename(tmp.Name(), pr.Name())
	if err == nil {
		return nil
	}

	// Otherwise, Windows doesn't let us rename over a locked file, so
	// we have to do a straight copy.  Unfortunately this could result
	// in a partially-written file if the process fails before the
	// copy completes.
	_, err = pr.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	err = pr.Truncate(0)
	if err != nil {
		return err
	}
	_, err = tmp.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}
	_, err = io.Copy(pr, tmp)
	return err
}
