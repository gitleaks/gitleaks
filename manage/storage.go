package manage

import "os"

// using repository pattern to make it possible test code without writing to disk
type FileSystemWriter interface {
	MkdirAll(path string, perm os.FileMode) error
	CreateTemp(dir, pattern string) (*os.File, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error
}

type osRepository struct{}

func (o osRepository) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (o osRepository) CreateTemp(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}

func (o osRepository) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (o osRepository) Remove(name string) error {
	return os.Remove(name)
}
