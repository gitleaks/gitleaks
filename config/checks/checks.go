package checks

import (
	"regexp/syntax"
)

// CheckPattern detects common pattern errors.
// - A word boundary (\b) is adjacent to a non-word character in the regex.
// - A character range ([a-z]) contains an invalid or strange character range.
// - TODO: Begins or ends with word characters and no boundary?
func CheckPattern(pattern string) error {
	// Parse the regex pattern into a syntax tree.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return err
	}

	// Recursively check if a word boundary is beside a non-word character.
	if err := checkWordBoundary(pattern, re); err != nil {
		return err
	}
	// TODO: Go simplifies things like `[./0-9]` to `[.-9]`. The current logic is prone to false-positives.
	// Recursively check for 'weird' char class ranges.
	//if err := checkCharClass(pattern, re); err != nil {
	//	return err
	//}
	return nil
}
