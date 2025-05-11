package codec

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

var (
	// encodingsRe is a regex built by combining all the encoding patterns
	// into named capture groups so that a single pass can detect multiple
	// encodings
	encodingsRe *regexp.Regexp
	// encodings contains all the encoding configurations for the detector.
	// The order is important. You want more specific encodings first or
	// encodings that partially encode the values (e.g. percent) unlike
	// encodings that fully encode the string (e.g. base64). If two
	// encoding matches touch the decoder will use this order to determine
	// which encoding should wait till the next pass. The pattern should be
	// should match the encoding fully and nothing else. The full match for
	// each encoding will be passed to its decode function.
	encodings = []*encoding{
		&encoding{
			kind:    percentKind,
			pattern: `(?:%[0-9A-Fa-f]{2})+`,
			decode:  decodePercent,
		},
		&encoding{
			kind:    hexKind,
			pattern: `[0-9A-Fa-f]{32,}`,
			decode:  decodeHex,
		},
		&encoding{
			kind:    base64Kind,
			pattern: `[\w\/+-]{16,}={0,2}`,
			decode:  decodeBase64,
		},
	}
)

// encodingNames is used to map the encodingKinds to their name
var encodingNames = []string{
	"percent",
	"hex",
	"base64",
}

// encodingKind can be or'd together to capture all of the unique encodings
// that were present in a segment
type encodingKind int

var (
	// make sure these go up by powers of 2
	percentKind = encodingKind(1)
	hexKind     = encodingKind(2)
	base64Kind  = encodingKind(4)
)

func (e encodingKind) String() string {
	i := int(math.Log2(float64(e)))
	if i >= len(encodingNames) {
		return ""
	}
	return encodingNames[i]
}

// kinds returns a list of encodingKinds combined in this one
func (e encodingKind) kinds() []encodingKind {
	kinds := []encodingKind{}

	for i := 0; i < len(encodingNames); i++ {
		if kind := int(e) & int(math.Pow(2, float64(i))); kind != 0 {
			kinds = append(kinds, encodingKind(kind))
		}
	}

	return kinds
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// the regex pattern that _only_ matches the encoding format
	pattern string
	// take the match and return the decoded value
	decode func(string) string
	// this gets set when the encodings list is built so that the
	// the encodings list doesn't need to be iterated over as many
	// times
	precedence int
}

func init() {
	count := len(encodings)
	namedPatterns := make([]string, count)
	for i, encoding := range encodings {
		encoding.precedence = count - i
		namedPatterns[i] = fmt.Sprintf(
			"(?P<%s>%s)",
			encoding.kind,
			encoding.pattern,
		)
	}
	encodingsRe = regexp.MustCompile(strings.Join(namedPatterns, "|"))
}

// findEncodingMatches uses the combined encodingsRe to find as many encodings
// as it can in a single pass
func findEncodingMatches(data string) ([]*encoding, [][]int) {
	matchIndices := encodingsRe.FindAllStringSubmatchIndex(data, -1)
	matchEncodings := make([]*encoding, len(matchIndices))
	for i, match := range matchIndices {
		matchEncodings[i] = getEncoding(match)
	}
	return matchEncodings, matchIndices
}

// getEncoding looks at the match group to figure out what kind of
// encoding was detected. This only works with match indices from encodingsRe
func getEncoding(matchIndex []int) *encoding {
	// No specific encoding was found. Not sure how we got here
	if len(matchIndex) < 4 {
		return nil
	}

	// Check which encoding was found
	for i, j := 2, 0; i < len(matchIndex); i, j = i+2, j+1 {
		if matchIndex[i] > -1 {
			return encodings[j]
		}
	}

	// No specific encoding was found. Not sure how we got here
	return nil
}
