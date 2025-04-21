package checks

import (
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"regexp/syntax"
	"testing"
)

func Test_checkCharClass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		patterns map[string]*InvalidRangeError
	}{
		// Valid
		{
			name: "valid word char patterns",
			patterns: map[string]*InvalidRangeError{
				`[a-z]`:         nil,
				`[A-Z]`:         nil,
				`[0-9]`:         nil,
				`[a-zA-Z0-9]`:   nil,
				`[a-zA-Z0-9_-]`: nil,
				`[\w]?`:         nil,
				`[\w]*`:         nil,
				`[\w]+`:         nil,
				`[\w]{1}`:       nil,
				`[\w]{1,2}`:     nil,
				`[\w]{1,}`:      nil,
			},
		},
		{
			name: "valid extended char range",
			patterns: map[string]*InvalidRangeError{
				`\$[.\/A-Za-z0-9]+`: nil, // Gets parsed as `[.-9]`
			},
		},
		{
			name: "valid negated char patterns",
			patterns: map[string]*InvalidRangeError{
				`[^\t\s]`: nil,
				`\boc\s+login\s+.*?--token\s*=?\s*(sha256~[^<\s]{16,})\b`: nil,
			},
		},

		// Invalid
		{
			name: "invalid non-word char range",
			patterns: map[string]*InvalidRangeError{
				`[a-zA-Z0-9=-_]`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`(?i)[a-lA-L0-9=-_]`: {
					Segment: `[0-9=-_a-zſK]`, // https://github.com/golang/go/issues/73456
					From:    '=',
					To:      '_',
				},
				`(?:a|[a-zA-Z0-9=-_])`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`(?:c|(?:a|[a-yA-Y0-9=-_])b)`: {
					Segment: `[0-9=-_a-y]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]?`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]*`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]+`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]{1}`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]{1,2}`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
				`[a-zA-Z0-9=-_]{1,}`: {
					Segment: `[0-9=-_a-z]`,
					From:    '=',
					To:      '_',
				},
			},
		},
		{
			name: "invalid word char range",
			patterns: map[string]*InvalidRangeError{
				`[0-9A-z]`: {
					Segment: `[0-9A-z]`,
					From:    'A',
					To:      'z',
				},
				`[0-Z]`: {
					Segment: `[0-Z]`,
					From:    '0',
					To:      'Z',
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for pattern, expected := range c.patterns {
				re, err := syntax.Parse(pattern, syntax.Perl)
				require.NoError(t, err)

				err = checkCharClass(pattern, re)
				if diff := cmp.Diff(expected, err); diff != "" {
					t.Errorf("diff: (-want +got)\n%s", diff)
				}
			}
		})
	}
}
