package sources

import (
	"iter"
)

// Source represents a thing that can be scanned
type Source interface {
	// Fragments returns an iterator of fragments to scan
	func Fragments() iter.Seq[Fragment]
}
