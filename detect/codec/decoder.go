package codec

import (
	"bytes"
	"github.com/zricethezav/gitleaks/v8/logging"
)

// Decoder decodes various types of data in place
type Decoder struct {
	decodedMap map[string]string
}

// NewDecoder creates a default decoder struct
func NewDecoder() *Decoder {
	return &Decoder{
		decodedMap: make(map[string]string),
	}
}

// Decode returns the data with the values decoded in place along with the
// encoded segment meta data for the next pass of decoding
func (d *Decoder) Decode(data string, parentSegments []EncodedSegment) (string, []EncodedSegment) {
	segments := d.findEncodedSegments(data, parentSegments)

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

// findEncodedSegments finds the encoded segments in the data and updates the
// segment tree for this pass
func (d *Decoder) findEncodedSegments(data string, parentSegments []EncodedSegment) []EncodedSegment {
	if len(data) == 0 {
		return []EncodedSegment{}
	}

	decodedShift := 0
	matchEncodings, matchIndices := findEncodingMatches(data)
	segments := make([]EncodedSegment, 0, len(matchIndices))
	for i, matchIndex := range matchIndices {
		encoding := matchEncodings[i]

		if encoding == nil {
			logging.Error().Msg("could not determine encoding")
			continue
		}
		if d.skipDecode(i, matchEncodings, matchIndices) {
			continue
		}

		encodedValue := data[matchIndex[0]:matchIndex[1]]
		decodedValue, alreadyDecoded := d.decodedMap[encodedValue]

		if !alreadyDecoded {
			decodedValue = encoding.decode(encodedValue)
			d.decodedMap[encodedValue] = decodedValue
		}

		if len(decodedValue) == 0 {
			continue
		}

		segment := EncodedSegment{
			relativeStart: matchIndex[0],
			relativeEnd:   matchIndex[1],
			absoluteStart: matchIndex[0],
			absoluteEnd:   matchIndex[1],
			decodedStart:  matchIndex[0] + decodedShift,
			decodedEnd:    matchIndex[0] + decodedShift + len(decodedValue),
			decodedValue:  decodedValue,
			encoding:      encoding.kind,
		}

		// Shift decoded start and ends based on size changes
		decodedShift += len(decodedValue) - len(encodedValue)

		// Adjust the absolute position of segments contained in parent segments
		for _, parentSegment := range parentSegments {
			if segment.isChildOf(parentSegment) {
				segment.absoluteStart = parentSegment.absoluteStart
				segment.absoluteEnd = parentSegment.absoluteEnd
				segment.parent = &parentSegment
				break
			}
		}

		segments = append(segments, segment)
		logging.Debug().Msgf(
			"segment found: enc=%q abs=[%d,%d] rel=[%d,%d]: %q -> %q",
			segment.encoding,
			segment.absoluteStart,
			segment.absoluteEnd,
			segment.relativeStart,
			segment.relativeEnd,
			encodedValue,
			segment.decodedValue,
		)
	}

	return segments

}

// skipDecode checks to see if this match touches any neigbors that are
// higher precedence. If so it returns true handle the lower precedence encoding
// on the next pass to avoid decoding issues.
func (d *Decoder) skipDecode(i int, encodings []*encoding, matchIndices [][]int) bool {
	count := len(matchIndices)
	if count == 1 {
		return false
	}

	thisMatch := matchIndices[i]
	thisEncoding := encodings[i]
	hasPrev := i > 0 && encodings[i-1] != nil
	hasNext := i+1 < count && encodings[i+1] != nil

	if hasPrev {
		prevMatch := matchIndices[i-1]
		prevEncoding := encodings[i-1]
		theyTouch := prevMatch[1] == thisMatch[0]
		prevIsHigherPrecedence := prevEncoding.precedence > thisEncoding.precedence
		if theyTouch && prevIsHigherPrecedence {
			return true
		}
	}

	if hasNext {
		nextMatch := matchIndices[i+1]
		nextEncoding := encodings[i+1]
		theyTouch := thisMatch[1] == nextMatch[0]
		nextIsHigherPrecedence := nextEncoding.precedence > thisEncoding.precedence
		if theyTouch && nextIsHigherPrecedence {
			return true
		}
	}

	return false
}
