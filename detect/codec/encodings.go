package codec

import (
	"math"
	"regexp"
	"sort"
)

var (
	// encodings contains all the encoding configurations for the detector.
	// The precedence is important. You want more specific encodings to
	// have a higher precedence or encodings that partially encode the
	// values (e.g. percent) unlike encodings that fully encode the string
	// (e.g. base64). If two encoding matches overlap the decoder will use
	// this order to determine which encoding should wait till the next pass.
	encodings = []*encoding{
		&encoding{
			kind:       percentKind,
			pattern:    regexp.MustCompile(`%[0-9A-Fa-f]{2}(?:.*%[0-9A-Fa-f]{2})?`),
			decode:     decodePercent,
			precedence: 3,
		},
		&encoding{
			kind:       hexKind,
			pattern:    regexp.MustCompile(`[0-9A-Fa-f]{32,}`),
			decode:     decodeHex,
			precedence: 2,
		},
		&encoding{
			kind:       base64Kind,
			pattern:    regexp.MustCompile(`[\w\/+-]{16,}={0,2}`),
			decode:     decodeBase64,
			precedence: 1,
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

type encodingMatch struct {
	encoding *encoding
	startEnd
}

// encoding represent a type of coding supported by the decoder.
type encoding struct {
	// the kind of decoding (e.g. base64, etc)
	kind encodingKind
	// the regex pattern that matches the encoding format
	pattern *regexp.Regexp
	// take the match and return the decoded value
	decode func(string) string
	// determine which encoding should win out when two overlap
	precedence int
}

// findEncodingMatches finds as many encodings can for this pass
func findEncodingMatches(data string) []encodingMatch {
	var all []encodingMatch
	for _, e := range encodings {
		for _, matchIndex := range e.pattern.FindAllStringIndex(data, -1) {
			all = append(all, encodingMatch{
				encoding: e,
				startEnd: startEnd{
					start: matchIndex[0],
					end:   matchIndex[1],
				},
			})
		}
	}

	// The rest of the code (both below and outside this function) expects
	// that these are sorted
	sort.Slice(all, func(i, j int) bool {
		return all[i].start < all[j].start
	})

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
