package sources

import (
	"context"
)

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment
type FragmentsFunc func(fragment Fragment, err error) error

// Source is a thing that can yield fragments
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source
	Fragments(ctx context.Context, yield FragmentsFunc) error
}
