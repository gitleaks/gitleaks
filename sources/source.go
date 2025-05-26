package sources

// FragmentsFunc is the type of function called by Fragments to yield the next
// fragment
type FragmentsFunc func(Fragment, error) error

// Source represents a thing that can be scanned
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source
	Fragments(FragmentsFunc) error
}
