package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetLocation tests the getLocation function.
func TestGetLocation(t *testing.T) {
	tests := []struct {
		name         string
		linePairs    [][]int
		raw          string
		start        int
		end          int
		wantLocation Location
	}{
		{
			name: "ASCII content - match on first line",
			linePairs: [][]int{
				{40, 41},
				{56, 57},
				{58, 59},
			},
			// Line 1: 40 chars + newline at byte 40
			// Line 2: 15 chars + newline at byte 56
			// Line 3: 1 char + newline at byte 58
			// total: 59 bytes
			raw:   "0123456789012345678901234567890123456789\n012345678901234\n0\n",
			start: 35,
			end:   38,
			wantLocation: Location{
				startLine:      0,
				startColumn:    36,
				endLine:        0,
				endColumn:      38,
				startLineIndex: 0,
				endLineIndex:   40,
			},
		},
		{
			name: "ASCII content - match on second line",
			linePairs: [][]int{
				{40, 41},
				{56, 57},
				{58, 59},
			},
			// newline is at byte 40, so line 2 starts at byte 41
			// byte 41 is '0' which is the first char of line 2
			raw:   "0123456789012345678901234567890123456789\n012345678901234\n0\n",
			start: 41,
			end:   45,
			wantLocation: Location{
				startLine:      1,
				startColumn:    2, // byte 41 is 1 byte after newline at 40, so column = 2 (1-indexed)
				endLine:        1,
				endColumn:      5, // 4 bytes after newline
				startLineIndex: 40,
				endLineIndex:   56,
			},
		},
		{
			name: "Unicode content - column should count codepoints not bytes",
			linePairs: [][]int{
				{19, 20}, // newline at byte 19 (total: 9 bytes for "日本語" + 10 bytes for "key=secret" = 19)
			},
			// "日本語key=secret\n" - total 20 bytes
			// "日本語" is 3 characters but 9 bytes (3 bytes each)
			// "key=secret" is 10 characters and 10 bytes
			raw:   "日本語key=secret\n",
			start: 9,  // byte index of 'k' (after 3 unicode chars = 9 bytes)
			end:   19, // byte index of newline (9 + 10 = 19)
			wantLocation: Location{
				startLine:      0,
				startColumn:    4, // "日本語" = 3 chars, so 'k' is at column 4
				endLine:        0,
				endColumn:      13, // 3 + 10 = 13 characters
				startLineIndex: 0,
				endLineIndex:   19,
			},
		},
		{
			name: "Unicode content - match within unicode characters",
			linePairs: [][]int{
				{21, 22}, // newline at byte 21 (6 + 9 + 6 = 21)
			},
			// "prefix日本語suffix\n" - total 22 bytes
			// "prefix" is 6 bytes, "日本語" is 9 bytes, "suffix" is 6 bytes = 21 bytes + newline
			raw:   "prefix日本語suffix\n",
			start: 6,  // byte index of first unicode char '日'
			end:   15, // byte index after '語' (6 + 9 = 15)
			wantLocation: Location{
				startLine:      0,
				startColumn:    7, // "prefix" is 6 chars, so '日' starts at column 7
				endLine:        0,
				endColumn:      9, // 6 + 3 = 9 characters
				startLineIndex: 0,
				endLineIndex:   21,
			},
		},
		{
			name: "Multi-byte emoji - column should count codepoints",
			linePairs: [][]int{
				{14, 15}, // newline at byte 14 (4 + 10 = 14)
			},
			// "🔑key=secret\n" - total 15 bytes
			// "🔑" is 4 bytes, "key=secret" is 10 bytes = 14 bytes + newline
			raw:   "🔑key=secret\n",
			start: 4,  // byte index of 'k' (after emoji = 4 bytes)
			end:   14, // byte index of newline (4 + 10 = 14)
			wantLocation: Location{
				startLine:      0,
				startColumn:    2, // "🔑" = 1 char, so 'k' is at column 2
				endLine:        0,
				endColumn:      11, // 1 + 10 = 11 characters
				startLineIndex: 0,
				endLineIndex:   14,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loc := location(test.linePairs, test.raw, []int{test.start, test.end})
			assert.Equal(t, test.wantLocation, loc)
		})
	}
}

func TestByteOffsetToRuneCount(t *testing.T) {
	tests := []struct {
		name       string
		s          string
		byteOffset int
		want       int
	}{
		{"empty string", "", 0, 0},
		{"ASCII only", "hello", 3, 3},
		{"ASCII full", "hello", 5, 5},
		{"unicode 3-byte chars", "日本語", 3, 1},           // first char
		{"unicode 3-byte chars", "日本語", 6, 2},           // two chars
		{"unicode 3-byte chars", "日本語", 9, 3},           // all three chars
		{"mixed ASCII and unicode", "abc日本語def", 3, 3},  // "abc"
		{"mixed ASCII and unicode", "abc日本語def", 6, 4},  // "abc日"
		{"mixed ASCII and unicode", "abc日本語def", 12, 6}, // "abc日本語"
		{"emoji 4-byte", "🔑key", 4, 1},                  // emoji is 1 char
		{"emoji 4-byte", "🔑key", 5, 2},                  // emoji + 'k'
		{"zero offset", "hello", 0, 0},
		{"negative offset", "hello", -1, 0},
		{"offset beyond length", "hello", 10, 5},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := byteOffsetToRuneCount(test.s, test.byteOffset)
			assert.Equal(t, test.want, got)
		})
	}
}
