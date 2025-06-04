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
	// The precedence is important. You want more specific encodings to
	// have a higher precedence or encodings that partially encode the
	// values (e.g. percent) unlike encodings that fully encode the string
	// (e.g. base64). If two encoding matches overlap the decoder will use
	// this order to determine which encoding should wait till the next pass.
	encodings = []*encoding{
		{
			kind:    percentKind,
			pattern: `%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?`,
			decode:  decodePercent,
		},
		{
			kind:    unicodeKind,
			pattern: `(?:(?:U\+[a-fA-F0-9]{4}(?:\s|$))+|(?i)(?:\\{1,2}u[a-fA-F0-9]{4})+)`,
			decode:  decodeUnicode,
		},
		{
			kind:    hexKind,
			pattern: `[0-9A-Fa-f]{32,}`,
			decode:  decodeHex,
		},
		{
			kind:    base64Kind,
			pattern: `[\w\/+-]{16,}={0,2}`,
			decode:  decodeBase64,
		},
	}
)

// encodingNames is used to map the encodingKinds to their name
var encodingNames = []string{
	"percent",
	"unicode",
	"hex",
	"base64",
}

// encodingKind can be or'd together to capture all of the unique encodings
// that were present in a segment
type encodingKind int

var (
	// make sure these go up by powers of 2
	percentKind = encodingKind(1)
	unicodeKind = encodingKind(2)
	hexKind     = encodingKind(4)
	base64Kind  = encodingKind(8)
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

// encodingMatch represents a match of an encoding in the text
type encodingMatch struct {
	encoding *encoding
	startEnd
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// the regex pattern that matches the encoding format
	pattern string
	// take the match and return the decoded value
	decode func(string) string
	// determine which encoding should win out when two overlap
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

// findEncodingMatches finds as many encodings as it can for this pass
func findEncodingMatches(data string) []encodingMatch {
	var all []encodingMatch
	for _, matchIndex := range encodingsRe.FindAllStringSubmatchIndex(data, -1) {
		// Add the encodingMatch with its proper encoding
		for i, j := 2, 0; i < len(matchIndex); i, j = i+2, j+1 {
			if matchIndex[i] > -1 {
				all = append(all, encodingMatch{
					encoding: encodings[j],
					startEnd: startEnd{
						start: matchIndex[i],
						end:   matchIndex[i+1],
					},
				})
			}
		}
	}

	totalMatches := len(all)
	if totalMatches == 1 {
		return all
	}

	// filter out lower precedence ones that overlap their neigbors
	filtered := make([]encodingMatch, 0, len(all))
	for i, m := range all {
		if i > 0 {
			prev := all[i-1]
			if m.overlaps(prev.startEnd) && prev.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		if i+1 < totalMatches {
			next := all[i+1]
			if m.overlaps(next.startEnd) && next.encoding.precedence > m.encoding.precedence {
				continue // skip this one
			}
		}
		filtered = append(filtered, m)
	}

	return filtered
}
