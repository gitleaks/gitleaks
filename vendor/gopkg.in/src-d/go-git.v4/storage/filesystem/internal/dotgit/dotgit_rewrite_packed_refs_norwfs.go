// +build norwfs

package dotgit

import (
	"io"
	"os"

	"gopkg.in/src-d/go-billy.v4"
)

const openAndLockPackedRefsMode = os.O_RDONLY

// Instead of renaming that can not be supported in simpler filesystems
// a full copy is done.
func (d *DotGit) rewritePackedRefsWhileLocked(
	tmp billy.File, pr billy.File) error {

	prWrite, err := d.fs.Create(pr.Name())
	if err != nil {
		return err
	}

	defer prWrite.Close()

	_, err = tmp.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	_, err = io.Copy(prWrite, tmp)

	return err
}
