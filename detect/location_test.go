package detect

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetLocation tests the location function.
func TestGetLocation(t *testing.T) {
	tests := []struct {
		name          string
		raw           string
		start         int
		end           int
		wantStartLine int
		wantEndLine   int
		wantStartCol  int
		wantEndCol    int
	}{
		{
			name:          "match on first line",
			raw:           "..f..\n..f..",
			start:         2,
			end:           3,
			wantStartLine: 0,
			wantEndLine:   0,
			wantStartCol:  3,
			wantEndCol:    3,
		},
		{
			name:          "match on last line",
			raw:           "..f..\n..f..",
			start:         8,
			end:           9,
			wantStartLine: 1,
			wantEndLine:   1,
			wantStartCol:  3,
			wantEndCol:    3,
		},
		{
			name:          "match on middle line",
			raw:           "first\nfoo\nthird",
			start:         6,
			end:           9,
			wantStartLine: 1,
			wantEndLine:   1,
			wantStartCol:  1,
			wantEndCol:    3,
		},
		{
			name:          "match after CRLF",
			raw:           "..f..\r\n..f..",
			start:         9,
			end:           10,
			wantStartLine: 1,
			wantEndLine:   1,
			wantStartCol:  3,
			wantEndCol:    3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			linePairs := newLineRegexp.FindAllStringIndex(test.raw, -1)
			loc := location(linePairs, test.raw, []int{test.start, test.end})
			assert.Equal(t, test.wantStartLine, loc.startLine)
			assert.Equal(t, test.wantEndLine, loc.endLine)
			assert.Equal(t, test.wantStartCol, loc.startColumn)
			assert.Equal(t, test.wantEndCol, loc.endColumn)
		})
	}
}
