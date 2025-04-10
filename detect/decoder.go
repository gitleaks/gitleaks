package detect

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/zricethezav/gitleaks/v8/logging"
)

var (
	// likelyB64Chars is a set of characters that you would expect to find
	// at least one of in base64 encoded data. This does risk missing
	// about 1% of base64 encoded data that doesn't contain these
	// characters, but gives you the performance gain of not trying to
	// decode things like most function definitions.
	likelyB64Chars [128]byte
	// encodingsRe contains all the patterns for finding different encoding
	// types and labeling them using a named capture group. In the current
	// implementation it's assumed that the match group and the full match
	// are equal (i.e. the pattern doesn't look for any context around
	// the match group). If that changes, make sure to update the way
	// matchIndices are referenced to reference the match group indices
	// instead of those the whole match.
	encodingsRe = regexp.MustCompile(
		strings.Join([]string{
			// The order here is important. If two matches touch
			// eachother, this order is used to determine which
			// encoding should be decoded on the first pass vs
			// decoded on a follow up pass. See d.skipDecode for
			// more information. For the rest of the comments,
			// this order will be called "decoding order".
			`(?P<percent>(?:%[0-9A-Fa-f]{2})+)`,
			`(?P<base64>[\w\/+-]{16,}={0,3})`,
		}, "|"),
	)
	// encodingNames is a list of the supported encodings the decoding
	// order.
	encodingNames = encodingsRe.SubexpNames()
	// decodingOrderMap is used by the decodingOrder function for
	// quicker lookups so that it doesn't have to iterate over the
	// encodingNames constantly
	decodingOrderMap = make(map[string]int, len(encodingNames))
)

func init() {
	// See above for an explination of how this is used
	for _, c := range `0123456789+/-_` {
		likelyB64Chars[c] = 1
	}
	// See above for an explination of how this is used
	for i, name := range encodingNames {
		decodingOrderMap[name] = i
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

	decodedShift := 0
	matchIndices := encodingsRe.FindAllStringSubmatchIndex(data, -1)
	segments := make([]EncodedSegment, 0, len(matchIndices))
	for i, matchIndex := range matchIndices {
		var decodeValue func(string) string
		// Handle decoding this segment in the next level of decoding.
		// See the comments for the function for more context.
		if d.skipDecode(i, matchIndices) {
			continue
		}

		encoding := getEncoding(matchIndex)
		switch encoding {
		case "percent":
			decodeValue = decodePercent
		case "base64":
			decodeValue = decodeBase64
		default:
			logging.Error().Msgf("invalid encoding: %q", encoding)
			continue
		}

		encodedValue := data[matchIndex[0]:matchIndex[1]]
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
			encoding:      encoding,
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
			"segment found: enc=%q abs=[%d,%d] rel=[%d,%d]",
			segment.encoding,
			segment.absoluteStart,
			segment.absoluteEnd,
			segment.relativeStart,
			segment.relativeEnd,
		)
	}

	return segments
}

// skipDecode checks to see if the current match has any neigbors that touch
// it and have an earlier decode order. If so it should be skipped until
// the neigbors are decoded. This helps prevent some cases where encodings
// can overlap eachother
func (d *Decoder) skipDecode(i int, matchIndices [][]int) bool {
	count := len(matchIndices)
	// Only one match has nothing to overlap with
	if count == 1 {
		return false
	}
	current := matchIndices[i]
	// Check current against the previous neigbor if it exists
	if hasPrev := i > 0; hasPrev {
		prev := matchIndices[i-1]
		// Check if prev touches and has an earlier decode order
		if prev[1] == current[0] && decodingOrder(prev) < decodingOrder(current) {
			return true
		}
	}
	// Check current against the next neigbor if it exists
	if hasNext := i+1 < count; hasNext {
		next := matchIndices[i+1]
		// Check if next touches and has an earlier decode order
		if current[1] == next[0] && decodingOrder(next) < decodingOrder(current) {
			return true
		}
	}
	// Woot! Nothing to skip!
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

// currentLine returns from the start of the line containing the segment
// to the end of the line where the segment ends.
func (s EncodedSegment) currentLine(currentRaw string) string {
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

// containsLikelyB64Char checks to see if at least one character is in
// likelyB64Chars
func containsLikelyB64Char(data string) bool {
	for _, c := range data {
		if likelyB64Chars[c] != 0 {
			return true
		}
	}

	return false
}

// getEncoding looks at the match group to figure out what kind of
// encoding was detected. This only works with match indices from encodingsRe
func getEncoding(matchIndex []int) string {
	// No specific encoding was found. Not sure how we got here
	if len(matchIndex) < 4 {
		return ""
	}

	// Check which encoding was found
	for i := 2; i < len(matchIndex); i += 2 {
		if matchIndex[i] > -1 {
			return encodingNames[int(i/2)]
		}
	}

	return ""
}

// decodeBase64 handles decoding both base64 and base64url encoded data
func decodeBase64(encodedValue string) string {
	// Exit early if it doesn't seem like base64
	if !containsLikelyB64Char(encodedValue) {
		return ""
	}

	// Try standard base64 decoding
	decodedValue, err := base64.StdEncoding.DecodeString(encodedValue)
	if err == nil && isASCII(decodedValue) {
		return string(decodedValue)
	}

	// Try base64url decoding
	decodedValue, err = base64.RawURLEncoding.DecodeString(encodedValue)
	if err == nil && isASCII(decodedValue) {
		return string(decodedValue)
	}

	// Nothing was able to be decoded
	return ""
}

// decodePercent decodes strings of percent encoded values only. It rejects
// text with non-percent encoded portions
func decodePercent(encodedValue string) string {
	encodedSize := len(encodedValue)
	// Each percent encoded value should be three characters long: %XX
	// where X is a hex digit. If this function gets anything other than
	// percent encoded values, it should return an empty string to indicate
	// an error decoding
	if encodedSize%3 != 0 {
		return ""
	}

	// TODO: see if it makes sense to keep a map of common values
	// to speed up decoding

	// Decode the values into a byte slice
	decodedValue := make([]byte, int(encodedSize/3))
	for i := 0; i+2 < encodedSize; i += 3 {
		// Must start with a percent
		if encodedValue[i] != '%' {
			return ""
		}

		// Get the two nybbles
		n1, n2 := encodedValue[i+1], encodedValue[i+2]

		// Confirm the nybbles are valid hex
		if !isHex(n1) || !isHex(n2) {
			return ""
		}

		// Decode the two nybbles into a byte
		decodedValue[int(i/3)] = unHex(n1)<<4 | unHex(n2)
	}

	// Make sure we're returning ascii text
	if !isASCII(decodedValue) {
		return ""
	}

	return string(decodedValue)
}

// unHex converts a byte to it's hex value
func unHex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}

	return 0
}

// isHex returns true if a byte is within [0-9A-Fa-f]
func isHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	}

	return false
}

// isASCII check to see if the text is in ASCII range
func isASCII(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] > unicode.MaxASCII || b[i] < '\t' {
			return false
		}
	}

	return true
}

// decodingOrder returns the index of the encoding name for this match to
// determine the priority
func decodingOrder(matchIndex []int) int {
	if i, ok := decodingOrderMap[getEncoding(matchIndex)]; ok {
		return i
	}
	return -1
}
