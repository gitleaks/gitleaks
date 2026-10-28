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
			location.startColumn = columnOf(raw, prevNewLine, start) + 1 // +1 because counting starts at 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = columnOf(raw, prevNewLine, end)
			location.endLineIndex = newLineByteIndex
		}

		prevNewLine = pair[0]
	}

	if !lineSet {
		// if lines never get set then that means the secret is most likely
		// on the last line of the diff output and the diff output does not have
		// a newline
		location.startColumn = columnOf(raw, prevNewLine, start) + 1 // +1 because counting starts at 1
		location.endColumn = columnOf(raw, prevNewLine, end)
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
	}
	return location
}

// columnOf returns how far into the line an offset is, counted in unicode
// codepoints rather than bytes.
//
// The SARIF specification defines startColumn and endColumn in codepoints, and
// subtracting byte offsets reported the byte distance instead: on a line
// holding any multi-byte character -- Arabic, CJK, an emoji -- the reported
// column pointed past where the secret actually is, and consumers that slice
// the line by column got the wrong text. For an all-ASCII line the two counts
// are identical, which is why this went unnoticed.
func columnOf(raw string, lineStart, offset int) int {
	if lineStart < 0 || offset > len(raw) || lineStart > offset {
		// Out of range: fall back to the byte distance rather than panic.
		return offset - lineStart
	}
	return utf8.RuneCountInString(raw[lineStart:offset])
}
