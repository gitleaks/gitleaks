package detect

// Location represents a location in a file
type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

func getLocation(linePairs [][]int, start int, end int) Location {
	var (
		prevNewLine int
		location    Location
	)

	for lineNum, pair := range linePairs {
		newLineByteIndex := pair[0]
		if prevNewLine <= start && start < newLineByteIndex {
			location.startLine = lineNum
			location.endLine = lineNum
			location.startColumn = (start - prevNewLine) + 1 // +1 because counting starts at 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = (end - prevNewLine)
			location.endLineIndex = newLineByteIndex
		}

		prevNewLine = pair[0]
	}

	return location
}
