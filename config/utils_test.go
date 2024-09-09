package config

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func Test_CheckPattern(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		patterns map[string]error
		invalid  bool
	}{
		// Valid
		{
			name: "word-boundary before word character",
			patterns: map[string]error{
				`\b\w`:                              nil,
				`\b\w*`:                             nil,
				`\b\w+`:                             nil,
				`\b\w?`:                             nil,
				`\b\w{10}`:                          nil,
				`\b\w{0,10}`:                        nil,
				`\b[A-Za-z0-9_]`:                    nil,
				`\b[A-Za-z0-9_]*`:                   nil,
				`\b[A-Za-z0-9_]+`:                   nil,
				`\b[A-Za-z0-9_]?`:                   nil,
				`\b[A-Za-z0-9_]{10}`:                nil,
				`\b[A-Za-z0-9_]{0,10}`:              nil,
				`\bvalid`:                           nil,
				`\b(foo1|bar2)`:                     nil,
				`\b(?:foo1|bar2)`:                   nil,
				`\b(?:foo1|(?:bar2)(?:baz3|-qux4))`: nil,
				`\bglpat-[\w-]{20}`:                 nil,
				`\b(?i:[0-9A-Z_a-zſK])`:             nil,
			},
			invalid: false,
		},
		{
			name: "word-boundary after word character",
			patterns: map[string]error{
				`\w\b`:                  nil,
				`\w*\b`:                 nil,
				`\w+\b`:                 nil,
				`\w?\b`:                 nil,
				`\w{10}\b`:              nil,
				`\w{0,10}\b`:            nil,
				`[A-Za-z0-9_]\b`:        nil,
				`[A-Za-z0-9_]*\b`:       nil,
				`[A-Za-z0-9_]+\b`:       nil,
				`[A-Za-z0-9_]?\b`:       nil,
				`[A-Za-z0-9_]{10}\b`:    nil,
				`[A-Za-z0-9_]{0,10}\b`:  nil,
				`valid\b`:               nil,
				`(foo1|bar2)\b`:         nil,
				`(?:foo1|bar2)\b`:       nil,
				`(?i:[0-9A-Z_a-zſK])\b`: nil,
			},
			invalid: false,
		},

		// Invalid
		{
			name: "lmao",
			patterns: map[string]error{
				`[^\t\n\f\r <]\ba`: nil,
			},
		}, // (?i:\bXOXE-[0-9]-[0-9A-Za-zſK]{146}\bJ)
		{
			name: "word-boundary before non-word character",
			patterns: map[string]error{
				`\b.`: &BoundaryMatchError{
					Segment: `(?-s:\b.)`,
					Before:  "^",
					After:   "(?-s:.)",
				},
				`\b-`: &BoundaryMatchError{
					Segment: `\b-`,
					Before:  "^",
					After:   "-",
				},
				`\b-*`: &BoundaryMatchError{
					Segment: `\b-*`,
					Before:  "^",
					After:   "-",
				},
				`\b-+`: &BoundaryMatchError{
					Segment: `\b-+`,
					Before:  "^",
					After:   "-",
				},
				`\b-?`: &BoundaryMatchError{
					Segment: `\b-?`,
					Before:  "^",
					After:   "-",
				},
				`\b-{10}`: &BoundaryMatchError{
					Segment: `\b-{10}`,
					Before:  "^",
					After:   "-",
				},
				`\b-{0,10}`: &BoundaryMatchError{
					Segment: `\b-{0,10}`,
					Before:  "^",
					After:   "-",
				},
				`\b[A-Za-z0-9_*-]`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]`,
					Before:  "^",
					After:   "*",
				},
				`\b[A-Za-z0-9_*-]*`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]*`,
					Before:  "^",
					After:   "*",
				},
				`\b[A-Za-z0-9_*-]+`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]+`,
					Before:  "^",
					After:   "*",
				},
				`\b[A-Za-z0-9_*-]?`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]?`,
					Before:  "^",
					After:   "*",
				},
				`\b[A-Za-z0-9_*-]{10}`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]{10}`,
					Before:  "^",
					After:   "*",
				},
				`\b[A-Za-z0-9_*-]{0,10}`: &BoundaryMatchError{
					Segment: `\b[\*\-0-9A-Z_a-z]{0,10}`,
					Before:  "^",
					After:   "*",
				},
				`\b-invalid`: &BoundaryMatchError{
					Segment: `\b-invalid`,
					Before:  "^",
					After:   "-",
				},
				`\b(-foo1|bar2)`: &BoundaryMatchError{
					Segment: `\b(-foo1|bar2)`,
					Before:  "^",
					After:   "-",
				},
				`\b(?:-foo1|bar2)`: &BoundaryMatchError{
					Segment: `\b(?:-foo1|bar2)`,
					Before:  "^",
					After:   "-",
				},
				`\b(?:foo1|(?:bar2)?(?:baz3|-qux4))`: &BoundaryMatchError{
					Segment: `\b(?:foo1|(?:bar2)?(?:baz3|-qux4))`,
					Before:  "^",
					After:   "-",
				},
				`\b(?:foo1|(?:bar2)?(?:baz3|(quux5|(?:-corge6|grault7)qux4)))`: &BoundaryMatchError{
					Segment: `\b(?:foo1|(?:bar2)?(?:baz3|(quux5|(?:-corge6|grault7)qux4)))`,
					Before:  "^",
					After:   "-",
				},
			},
			invalid: true,
		},
		{
			name: "word-boundary after non-word character",
			patterns: map[string]error{
				`.\b`: &BoundaryMatchError{
					Segment: `(?-s:.\b)`,
					Before:  "(?-s:.)",
					After:   "$",
				},
				`-\b`: &BoundaryMatchError{
					Segment: `-\b`,
					Before:  "-",
					After:   "$",
				},
				`-*\b`: &BoundaryMatchError{
					Segment: `-*\b`,
					Before:  "-",
					After:   "$",
				},
				`-+\b`: &BoundaryMatchError{
					Segment: `-+\b`,
					Before:  "-",
					After:   "$",
				},
				`-?\b`: &BoundaryMatchError{
					Segment: `-?\b`,
					Before:  "-",
					After:   "$",
				},
				`-{10}\b`: &BoundaryMatchError{
					Segment: `-{10}\b`,
					Before:  "-",
					After:   "$",
				},
				`-{0,10}\b`: &BoundaryMatchError{
					Segment: `-{0,10}\b`,
					Before:  "-",
					After:   "$",
				},
				`[A-Za-z0-9_*-]\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]\b`,
					Before:  "*",
					After:   "$",
				},
				`[A-Za-z0-9_*-]*\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]*\b`,
					Before:  "*",
					After:   "$",
				},
				`[A-Za-z0-9_*-]+\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]+\b`,
					Before:  "*",
					After:   "$",
				},
				`[A-Za-z0-9_*-]?\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]?\b`,
					Before:  "*",
					After:   "$",
				},
				`[A-Za-z0-9_*-]{10}\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]{10}\b`,
					Before:  "*",
					After:   "$",
				},
				`[A-Za-z0-9_*-]{0,10}\b`: &BoundaryMatchError{
					Segment: `[\*\-0-9A-Z_a-z]{0,10}\b`,
					Before:  "*",
					After:   "$",
				},
				`invalid-\b`: &BoundaryMatchError{
					Segment: `invalid-\b`,
					Before:  "-",
					After:   "$",
				},
				`(foo1|bar2-)\b`: &BoundaryMatchError{
					Segment: `(foo1|bar2-)\b`,
					Before:  "-",
					After:   "$",
				},
				`(?:foo1|bar2-)\b`: &BoundaryMatchError{
					Segment: `(?:foo1|bar2-)\b`,
					Before:  "-",
					After:   "$",
				},
				`(?:foo1|(?:baz3|qux4-)(?:bar2)?)\b`: &BoundaryMatchError{
					Segment: `(?:foo1|(?:baz3|qux4-)(?:bar2)?)\b`,
					Before:  "-",
					After:   "$",
				},
				`(?:foo1|(?:baz3|qux4(quux5|(?:corge6-|grault7)))(?:bar2)?)\b`: &BoundaryMatchError{
					Segment: `(?:foo1|(?:baz3|qux4(quux5|corge6-|grault7))(?:bar2)?)\b`,
					Before:  "-",
					After:   "$",
				},
				`glpat-[\w-]{20}\b`: &BoundaryMatchError{
					Segment: `glpat-[\-0-9A-Z_a-z]{20}\b`,
					Before:  "-",
					After:   "$",
				},
			},
			invalid: true,
		},
		{
			name: "word-boundary between word characters",
			patterns: map[string]error{
				`a\bc`: &BoundaryMatchError{
					Segment:      `a\bc`,
					Before:       "a",
					BeforeIsWord: true,
					After:        "c",
					AfterIsWord:  true,
				},
				// TODO
				//`[a-z-]\bc`: &BoundaryMatchError{
				//	Segment:      `a\bc`,
				//	Before:       "a",
				//	BeforeIsWord: true,
				//	After:        "c",
				//	AfterIsWord:  true,
				//},
				`(?i)\bxoxe-\d-[a-z0-9]{146}\bj`: &BoundaryMatchError{
					Segment:      `(?i:\bXOXE-[0-9]-[0-9A-Za-zſK]{146}\bJ)`,
					Before:       "a-z",
					BeforeIsWord: true,
					After:        "J",
					AfterIsWord:  true,
				},
			},
			invalid: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for pattern, expected := range c.patterns {
				err := CheckPattern(pattern)
				if diff := cmp.Diff(expected, err); diff != "" {
					t.Errorf("diff: (-want +got)\n%s", diff)
				}
			}
		})
	}
}

func Test_isWordCharacter(t *testing.T) {
	wordChar := regexp.MustCompile(`^\w$`)
	regexp.MustCompile(`[9-A]`)
	tests := []struct {
		name       string
		characters []rune
		expected   bool
	}{
		{
			name: "valid - alphanumeric",
			characters: func() []rune {
				var runes []rune
				for r := rune(32); r <= 126; r++ {
					if wordChar.MatchString(string(r)) {
						runes = append(runes, r)
					}
				}
				return runes
			}(),
			expected: true,
		},
		{
			name: "invalid - non-word chars",
			characters: func() []rune {
				var runes []rune
				for r := rune(32); r <= 126; r++ {
					if !wordChar.MatchString(string(r)) {
						runes = append(runes, r)
					}
				}
				return runes
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, character := range tt.characters {
				actual := isWordCharacter(character)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}

func Test_isWordCharacterRange(t *testing.T) {
	tests := []struct {
		name    string
		from    rune
		to      rune
		want    bool
		wantErr error
	}{
		// Valid - common
		{
			name: "lowercase: [a-z]",
			from: 'a',
			to:   'z',
			want: true,
		},
		{
			name: "uppercase: [A-Z]",
			from: 'A',
			to:   'Z',
			want: true,
		},
		{
			name: "digits: [0-9]",
			from: '0',
			to:   '9',
			want: true,
		},
		// Valid - uncommon
		{
			name: "base32: [2-7]",
			from: '2',
			to:   '7',
			want: true,
		},

		// Invalid
		{
			name:    "accidental: [A-Z_-=]",
			from:    '_',
			to:      '=',
			wantErr: errors.New("invalid character range: ['_', '='] in ``"),
		},
		{
			name:    "nonsensical: [09-A]",
			from:    '9',
			to:      'A',
			wantErr: errors.New("invalid character range: ['9', 'A'] in ``"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the regex pattern into a syntax tree.
			got, err := isWordCharacterRange(nil, tt.from, tt.to)
			if err != tt.wantErr {
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					require.NoError(t, err)
				}
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}
