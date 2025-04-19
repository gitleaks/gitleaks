package codec

import (
	"strconv"
)

// EncodedSegment represents a portion of text that is encoded in some way.
// `decode` supports recusive decoding and can result in "segment trees".
// There can be multiple segments in the original text, so each can be thought
// of as its own tree with the root being the original segment.
type EncodedSegment struct {
	// The parent segment in a segment tree. If nil, it is a root segment
	parent *EncodedSegment

	// Relative start/end are the bounds of the encoded value in the current pass.
	relativeStart int
	relativeEnd   int

	// Absolute start/end refer to the bounds of the root segment in this segment
	// tree
	absoluteStart int
	absoluteEnd   int

	// Decoded start/end refer to the bounds of the decoded value in the current
	// pass. These can differ from relative values because decoding can shrink
	// or grow the size of the segment.
	decodedStart int
	decodedEnd   int

	// This is the actual decoded content in the segment
	decodedValue string

	// This is the kind of encoding
	encoding string
}

// isChildOf inspects the bounds of two segments to determine
// if one should be the child of another
func (s EncodedSegment) isChildOf(parent EncodedSegment) bool {
	return parent.decodedStart <= s.relativeStart && parent.decodedEnd >= s.relativeEnd
}

// decodedOverlaps checks if the decoded bounds of the segment overlaps a range
func (s EncodedSegment) decodedOverlaps(start, end int) bool {
	return start <= s.decodedEnd && end >= s.decodedStart
}

// AdjustMatchIndex takes the matchIndex from the current decoding pass and
// updates it to match the absolute matchIndex in the original text.
func (s EncodedSegment) AdjustMatchIndex(matchIndex []int) []int {
	// The match is within the bounds of the segment so we just return
	// the absolute start and end of the root segment.
	if s.decodedStart <= matchIndex[0] && matchIndex[1] <= s.decodedEnd {
		return []int{
			s.absoluteStart,
			s.absoluteEnd,
		}
	}

	// Since it overlaps one side and/or the other, we're going to have to adjust
	// and climb parents until we're either at the root or we've determined
	// we're fully inside one of the parent segments.
	adjustedMatchIndex := make([]int, 2)
	if matchIndex[0] < s.decodedStart {
		// It starts before the encoded segment so adjust the start to match
		// the location before it was decoded
		matchStartDelta := s.decodedStart - matchIndex[0]
		adjustedMatchIndex[0] = s.relativeStart - matchStartDelta
	} else {
		// It starts within the encoded segment so set the bound to the
		// relative start
		adjustedMatchIndex[0] = s.relativeStart
	}

	if matchIndex[1] > s.decodedEnd {
		// It ends after the encoded segment so adjust the end to match
		// the location before it was decoded
		matchEndDelta := matchIndex[1] - s.decodedEnd
		adjustedMatchIndex[1] = s.relativeEnd + matchEndDelta
	} else {
		// It ends within the encoded segment so set the bound to the relative end
		adjustedMatchIndex[1] = s.relativeEnd
	}

	// We're still not at a root segment so we'll need to keep on adjusting
	if s.parent != nil {
		return s.parent.AdjustMatchIndex(adjustedMatchIndex)
	}

	return adjustedMatchIndex
}

// Tags returns additional meta data tags related to the types of segments
func (s EncodedSegment) Tags() []string {
	// Find the depth of this item and all the unique encodings
	depth, encodings := 0, make(map[string]bool)
	for current := &s; current != nil; current = current.parent {
		depth++
		encodings[current.encoding] = true
	}

	// Generate tags
	tags := make([]string, 0, len(encodings)+1)
	for encoding := range encodings {
		tags = append(tags, "decoded:"+encoding)
	}
	return append(tags, "decode-depth:"+strconv.Itoa(depth))
}

// CurrentLine returns from the start of the line containing the segment
// to the end of the line where the segment ends.
func (s EncodedSegment) CurrentLine(currentRaw string) string {
	start := 0
	end := len(currentRaw)

	// Find the start of the range
	for i := s.decodedStart; i > -1; i-- {
		c := currentRaw[i]
		if c == '\n' {
			start = i
			break
		}
	}

	// Find the end of the range
	for i := s.decodedEnd; i < end; i++ {
		c := currentRaw[i]
		if c == '\n' {
			end = i
			break
		}
	}

	return currentRaw[start:end]
}

// SegmentWithDecodedOverlap finds a segment where the decoded bounds overlaps
// a range
func SegmentWithDecodedOverlap(encodedSegments []EncodedSegment, start, end int) *EncodedSegment {
	for _, segment := range encodedSegments {
		if segment.decodedOverlaps(start, end) {
			return &segment
		}
	}
	return nil
}
