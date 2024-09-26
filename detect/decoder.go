package detect

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"unicode"

	"github.com/rs/zerolog/log"
)

var b64Regexp = regexp.MustCompile(`[\w\/\-\+]{16,}={0,3}`)
var decoders = []func(string) ([]byte, error){
	base64.StdEncoding.DecodeString,
	base64.RawURLEncoding.DecodeString,
}

// EncodedSegment represents a portion of text that is encoded some way.
// Decoded values can also have encoded text in them so there can be a kind of
// tree of segments needing to be decoded. This is why the term parent is used
// in a few places below.
type EncodedSegment struct {
	// The segment that this segment was found in after it was decoded
	parent *EncodedSegment

	// relative vs absolute vs decoded values:
	//
	// If a value is double encoded, multiple passes happen do decode it all.
	// Relative values are the bounds of the encoded value in the current pass.
	// Absolute values refer to the bounds of the original encoded segment so
	// that we can keep track of locations in the original data.
	//
	// When values are decoded they tend to shrink or grow depending on how they
	// are encoded. decodedStart and decodedEnd track the bounds of the segments
	// in the decoded version of the file.
	relativeStart int
	relativeEnd   int
	absoluteStart int
	absoluteEnd   int
	decodedStart  int
	decodedEnd    int
	decodedValue  string
}

// isContainedInParent figures out if this segment is contained in a parent
// segment (i.e. it was encoded multiple times)
func (s EncodedSegment) isContainedInParent(parent EncodedSegment) bool {
	return parent.decodedStart <= s.relativeStart && parent.decodedEnd >= s.relativeEnd
}

// decodedOverlaps checks if the decoded bounds of the segment overlaps a range
func (s EncodedSegment) decodedOverlaps(start, end int) bool {
	return start <= s.decodedEnd && end >= s.decodedStart
}

// adjustMatchIndex takes the index from the current decoding pass and updates
// it to match the right location in the original text.
//
// If the match is completely within the bounds of an encoded value in the
// original text, then the absolute bounds of that encoded value will be
// set.
//
// If the match goes outside of an encoded value in the original text then
// we start climbing the tree of segments to figure out if it overlaps
// the segment in the original text
func (s EncodedSegment) adjustMatchIndex(matchIndex []int) []int {
	// The match is within the bounds of the segment so we just return
	// the start and end of the root segment
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
		return s.parent.adjustMatchIndex(adjustedMatchIndex)
	}

	return adjustedMatchIndex
}

// decode returns the data with the values decoded in-place
func decode(data string, parentSegments []EncodedSegment) (string, []EncodedSegment) {
	segments := findEncodedSegments(data, parentSegments)

	if len(segments) > 0 {
		result := bytes.NewBuffer(make([]byte, 0, len(data)))

		relativeStart := 0
		for _, segment := range segments {
			result.WriteString(data[relativeStart:segment.relativeStart])
			result.WriteString(segment.decodedValue)
			relativeStart = segment.relativeEnd
		}
		result.WriteString(data[relativeStart:])

		return result.String(), segments
	}

	return data, segments
}

// findEncodedSegments finds the encoded segments in the data and maps them to
// any parent segments from a previous pass.
func findEncodedSegments(data string, parentSegments []EncodedSegment) []EncodedSegment {
	if len(data) == 0 {
		return []EncodedSegment{}
	}

	matchIndices := b64Regexp.FindAllStringIndex(data, -1)
	if matchIndices == nil {
		return []EncodedSegment{}
	}

	segments := make([]EncodedSegment, 0, len(matchIndices))
	decodedMap := make(map[string]string, len(matchIndices))

	// Keeps up with offsets from the text changing size as things are decoded
	decodedShift := 0

	for _, matchIndex := range matchIndices {
		encodedValue := data[matchIndex[0]:matchIndex[1]]
		decodedValue, alreadyDecoded := decodedMap[encodedValue]

		// We haven't decoded this yet, so go ahead and decode it
		if !alreadyDecoded {
			decodedValue = decodeValue(encodedValue)
			decodedMap[encodedValue] = decodedValue
		}

		// Skip this segment because there was nothing to check
		if len(decodedValue) == 0 {
			continue
		}

		// Create a segment for the encoded data
		segment := EncodedSegment{
			relativeStart: matchIndex[0],
			relativeEnd:   matchIndex[1],
			absoluteStart: matchIndex[0],
			absoluteEnd:   matchIndex[1],
			decodedStart:  matchIndex[0] + decodedShift,
			decodedEnd:    matchIndex[0] + decodedShift + len(decodedValue),
			decodedValue:  decodedValue,
		}

		// Shift decoded start and ends based on size changes
		decodedShift += len(decodedValue) - len(encodedValue)

		// Adjust the absolute position of segments contained in parent segments
		for _, parentSegment := range parentSegments {
			if segment.isContainedInParent(parentSegment) {
				segment.absoluteStart = parentSegment.absoluteStart
				segment.absoluteEnd = parentSegment.absoluteEnd
				segment.parent = &parentSegment
				break
			}
		}

		log.Debug().Msgf("segment found: %#v", segment)
		segments = append(segments, segment)
	}

	return segments
}

// decoders tries a list of decoders and returns the first successful one
func decodeValue(encodedValue string) string {
	for _, decoder := range decoders {
		decodedValue, err := decoder(encodedValue)

		if err == nil && len(decodedValue) > 0 && isASCII(decodedValue) {
			return string(decodedValue)
		}
	}

	return ""
}

func isASCII(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] > unicode.MaxASCII || b[i] < '\t' {
			return false
		}
	}

	return true
}

// Find a segment where the decoded bounds overlaps a range
func segmentWithDecodedOverlap(encodedSegments []EncodedSegment, start, end int) *EncodedSegment {
	for _, segment := range encodedSegments {
		if segment.decodedOverlaps(start, end) {
			return &segment
		}
	}

	return nil
}
