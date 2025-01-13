package detect

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"unicode"

	"github.com/zricethezav/gitleaks/v8/logging"
)

var b64LikelyChars [128]byte
var b64Regexp = regexp.MustCompile(`[\w/+-]{16,}={0,3}`)
var decoders = []func(string) ([]byte, error){
	base64.StdEncoding.DecodeString,
	base64.RawURLEncoding.DecodeString,
}

func init() {
	// Basically look for anything that isn't just letters
	for _, c := range `0123456789+/-_` {
		b64LikelyChars[c] = 1
	}
}

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

	// This is the type of encoding
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

// adjustMatchIndex takes the matchIndex from the current decoding pass and
// updates it to match the absolute matchIndex in the original text.
func (s EncodedSegment) adjustMatchIndex(matchIndex []int) []int {
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
		return s.parent.adjustMatchIndex(adjustedMatchIndex)
	}

	return adjustedMatchIndex
}

// depth reports how many levels of decoding needed to be done (default is 1)
func (s EncodedSegment) depth() int {
	depth := 1

	// Climb the tree and increment the depth
	for current := &s; current.parent != nil; current = current.parent {
		depth++
	}

	return depth
}

// tags returns additional meta data tags related to the types of segments
func (s EncodedSegment) tags() []string {
	return []string{
		fmt.Sprintf("decoded:%s", s.encoding),
		fmt.Sprintf("decode-depth:%d", s.depth()),
	}
}

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

// decode returns the data with the values decoded in-place
func (d *Decoder) decode(data string, parentSegments []EncodedSegment) (string, []EncodedSegment) {
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

	matchIndices := b64Regexp.FindAllStringIndex(data, -1)
	if matchIndices == nil {
		return []EncodedSegment{}
	}

	segments := make([]EncodedSegment, 0, len(matchIndices))

	// Keeps up with offsets from the text changing size as things are decoded
	decodedShift := 0

	for _, matchIndex := range matchIndices {
		encodedValue := data[matchIndex[0]:matchIndex[1]]

		if !isLikelyB64(encodedValue) {
			d.decodedMap[encodedValue] = ""
			continue
		}

		decodedValue, alreadyDecoded := d.decodedMap[encodedValue]

		// We haven't decoded this yet, so go ahead and decode it
		if !alreadyDecoded {
			decodedValue = decodeValue(encodedValue)
			d.decodedMap[encodedValue] = decodedValue
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
			encoding:      "base64",
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

		logging.Debug().Msgf("segment found: %#v", segment)
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

// Skip a lot of method signatures and things at the risk of missing about
// 1% of base64
func isLikelyB64(s string) bool {
	for _, c := range s {
		if b64LikelyChars[c] != 0 {
			return true
		}
	}

	return false
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
