package detect

import "unicode/utf8"

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

// byteOffsetToRuneCount converts a byte offset within a string to a rune (character) count.
// This is used to calculate column numbers as unicode codepoints rather than bytes.
func byteOffsetToRuneCount(s string, byteOffset int) int {
	if byteOffset <= 0 {
		return 0
	}
	if byteOffset >= len(s) {
		return utf8.RuneCountInString(s)
	}
	return utf8.RuneCountInString(s[:byteOffset])
}

func location(newlineIndices [][]int, raw string, matchIndex []int) Location {
	var (
		prevNewLine int
		location    Location
		lineSet     bool
		_lineNum    int
	)

	start := matchIndex[0]
	end := matchIndex[1]

	// default startLineIndex to 0
	location.startLineIndex = 0

	// Fixes: https://github.com/zricethezav/gitleaks/issues/1037
	// When a fragment does NOT have any newlines, a default "newline"
	// will be counted to make the subsequent location calculation logic work
	// for fragments will no newlines.
	if len(newlineIndices) == 0 {
		newlineIndices = [][]int{
			{len(raw), len(raw) + 1},
		}
	}

	for lineNum, pair := range newlineIndices {
		_lineNum = lineNum
		newLineByteIndex := pair[0]
		if prevNewLine <= start && start < newLineByteIndex {
			lineSet = true
			location.startLine = lineNum
			location.endLine = lineNum
			// Calculate column as unicode codepoints (runes) instead of bytes
			// Extract the line content and convert byte offset to rune count
			lineContent := raw[prevNewLine:newLineByteIndex]
			location.startColumn = byteOffsetToRuneCount(lineContent, start-prevNewLine) + 1 // +1 because counting starts at 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			// Calculate column as unicode codepoints (runes) instead of bytes
			lineContent := raw[prevNewLine:newLineByteIndex]
			location.endColumn = byteOffsetToRuneCount(lineContent, end-prevNewLine)
			location.endLineIndex = newLineByteIndex
		}

		prevNewLine = pair[0]
	}

	if !lineSet {
		// if lines never get set then that means the secret is most likely
		// on the last line of the diff output and the diff output does not have
		// a newline
		location.startLine = _lineNum + 1
		location.endLine = _lineNum + 1

		// search for new line byte index
		i := 0
		for end+i < len(raw) {
			if raw[end+i] == '\n' {
				break
			}
			if raw[end+i] == '\r' {
				break
			}
			i++
		}
		location.endLineIndex = end + i

		// Calculate columns as unicode codepoints (runes) instead of bytes
		lineContent := raw[prevNewLine:location.endLineIndex]
		location.startColumn = byteOffsetToRuneCount(lineContent, start-prevNewLine) + 1 // +1 because counting starts at 1
		location.endColumn = byteOffsetToRuneCount(lineContent, end-prevNewLine)
	}
	return location
}
