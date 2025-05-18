package sources

type FragmentsFunc func(Fragment, error) error

// Source represents a thing that can be scanned
type Source interface {
	// Fragments provides a filepath.WalkDir like interface for scanning the
	// fragments in the source
	Fragments(FragmentsFunc) error
}
