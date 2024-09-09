package config

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"unicode"

	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func anyRegexMatch(f string, res []*regexp.Regexp) bool {
	for _, re := range res {
		if regexMatched(f, re) {
			return true
		}
	}
	return false
}

func regexMatched(f string, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if re.FindString(f) != "" {
		return true
	}
	return false
}

type BoundaryMatchError struct {
	Segment      string
	Before       string
	BeforeIsWord bool
	After        string
	AfterIsWord  bool
}

func (e *BoundaryMatchError) Error() string {
	return fmt.Sprintf("invalid use of \\b: must between word ([A-Za-z0-9_]) and non-word characters, found [%q, \\b, %q] in `%s`", e.Before, e.After, e.Segment)
}

type InvalidRangeError struct {
	Segment string
	From    rune
	To      rune
}

func (e *InvalidRangeError) Error() string {
	return fmt.Sprintf("invalid character range: [%q, %q] in `%s`", e.From, e.To, e.Segment)
}

// CheckPattern detects common pattern errors.
// - A word boundary (\b) is adjacent to a non-word character in the regex.
// - A character range ([a-z]) contains an invalid or strange character range.
// - TODO: Begins or ends with word characters and no boundary?
func CheckPattern(pattern string) error {
	// Parse the regex pattern into a syntax tree.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return err
	}

	logging.Debug().Msgf("Checking pattern: %s", pattern)
	// Recursively check if a word boundary is beside a non-word character.
	if m := checkBoundary(re); m != nil {
		return m
	}
	return nil
}

// CheckBoundary traverses the parsed regex tree and checks for word boundaries adjacent to non-word characters.
func checkBoundary(re *syntax.Regexp) error {
	logging.Debug().Msgf("[checkBoundary] testing, re = %v, sub = %v", re, re.Sub)
	for i, sub := range re.Sub {
		// Check if the current node is a word boundary.
		if sub.Op == syntax.OpWordBoundary {
			var (
				bm = &BoundaryMatchError{
					Segment: re.String(),
				}
				before *syntax.Regexp
				after  *syntax.Regexp
			)
			if i > 0 {
				before = re.Sub[i-1]
				logging.Debug().Msgf("[checkBoundary] before = %v (%v)", before, before.Op)
			} else {
				bm.Before = "^"
			}
			if i < len(re.Sub)-1 {
				after = re.Sub[i+1]
				logging.Debug().Msgf("[checkBoundary] after = %v (%v)", after, after.Op)
			} else {
				bm.After = "$"
			}

			// Check if the next or previous node is a non-word character.
			if i > 0 {
				ok, match, err := isNonWordChar(before, true)
				if err != nil {
					return err
				}

				bm.Before = match
				if !ok {
					bm.BeforeIsWord = true
				}
			}
			if i < len(re.Sub)-1 {
				ok, match, err := isNonWordChar(after, false)
				if err != nil {
					return err
				}

				bm.After = match
				if !ok {
					bm.AfterIsWord = true
				}
			}

			if bm.BeforeIsWord == bm.AfterIsWord {
				return bm
			}
			logging.Debug().Msgf("[checkBoundary] word character: before = %v, after = %v", before, after)
		}

		// Recursively check sub-expressions.
		if m := checkBoundary(sub); m != nil {
			return m
		}
	}
	return nil
}

// IsNonWordChar checks if the regex node represents a non-word character.
func isNonWordChar(re *syntax.Regexp, before bool) (isNonWord bool, match string, err error) {
	if re.Op == syntax.OpRepeat || re.Op == syntax.OpStar || re.Op == syntax.OpPlus {
		re = re.Sub[0]
	}

	switch re.Op {
	case syntax.OpAnyChar, // .
		syntax.OpAnyCharNotNL: // (?-s:.)
		return true, re.String(), nil
	case syntax.OpLiteral: // a
		var r rune
		// Check if the literal contains non-word character (anything not [a-zA-Z0-9_]).
		if before {
			// Check the rune at the end of "before".
			r = re.Rune[len(re.Rune)-1]
		} else {
			// Check the rune at the start of "after".
			r = re.Rune[0]
		}
		return !isWordCharacter(r), string(r), nil
	case syntax.OpCharClass: // [a-z0-9]
		// Check if the character class contains only non-word characters.
		for i := 0; i < len(re.Rune); i += 2 {
			from, to := re.Rune[i], re.Rune[i+1]
			// Single character
			if from == to {
				switch from {
				case 0x17f, 0x212a:
					// Golang internally optimizes `(?i)[\w]` into `[0-9A-Z_a-zſK]`.
					// I don't know why this optimization exists, only that we should ignore them.
					// https://github.com/golang/go/blob/a11643df8ff8a575abe4abc7f25d09631424ea49/src/regexp/syntax/parse_test.go#L235-L236
					continue
				default:
					match = string(from)
					return !isWordCharacter(from), match, nil
				}
			}

			// Character range.
			match = string(from) + "-" + string(to)
			ok, err := isWordCharacterRange(re, from, to)
			if err != nil {
				return false, "", err
			}
			if !ok {
				return true, match, nil
			}
		}
	case syntax.OpCapture, // (a|b)
		syntax.OpAlternate: // (?:a|b)
		logging.Debug().Msgf("[isNonWordChar#cap/alt] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		for _, sub := range re.Sub {
			ok, match, err := isNonWordChar(sub, before)
			if err != nil {
				return false, "", err
			}
			if ok {
				return true, match, nil
			}
		}
	case syntax.OpConcat: // (?:foo)bar
		logging.Debug().Msgf("[isNonWordChar#con] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)

		var r *syntax.Regexp
		if before {
			r = re.Sub[len(re.Sub)-1]
		} else {
			r = re.Sub[0]
		}

		if r.Op == syntax.OpQuest {
			logging.Debug().Msgf("Info quest before! r = %v", r)
			for _, sub := range re.Sub {
				logging.Debug().Msgf("[isNonWordChar#concat/before] quest s = %v", sub)
				ok, match, err := isNonWordChar(sub, before)
				if err != nil {
					return false, "", err
				}
				if ok {
					return true, match, nil
				}
			}
		} else {
			for _, sub := range r.Sub {
				logging.Debug().Msgf("[isNonWordChar#concat/before] s = %v", sub)
				ok, match, err := isNonWordChar(sub, before)
				if err != nil {
					return false, "", err
				}
				if ok {
					return true, match, nil
				}
			}
		}

		ok, match, err := isNonWordChar(r, before)
		if err != nil {
			return false, "", err
		}
		if ok {
			return true, match, nil
		}
	case syntax.OpQuest: // a?
		logging.Debug().Msgf("[isNonWordChar#quest] is: op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		for _, sub := range re.Sub {
			logging.Debug().Msgf("[isNonWordChar#quest/sub] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
			ok, match, err := isNonWordChar(sub, before)
			if err != nil {
				return false, "", err
			}
			if ok {
				return true, match, nil
			}
		}
	case syntax.OpWordBoundary:
		var (
			b   *BoundaryMatchError
			err = checkBoundary(re)
		)
		if errors.As(err, &b) {
			return true, b.After, nil
		}
		return false, "", err
	default:
		logging.Fatal().Msgf("unhandled: op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
	}
	return false, match, nil
}

// isWordCharacter returns whether |r| matches `\w`.
func isWordCharacter(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isWordCharacterRange(re *syntax.Regexp, from rune, to rune) (bool, error) {
	switch {
	case (from >= '0' && from < '9') && (to > '0' && to <= '9'):
		return true, nil
	case (from >= 'A' && from < 'Z') && (to > 'A' && to <= 'Z'):
		return true, nil
	case (from >= 'a' && from < 'z') && (to > 'a' && to <= 'z'):
		return true, nil
	default:
		// TODO: Handle negated ranges [^a-z].
		if from == 0x00 {
			return false, nil
		}

		var segment string
		if re != nil {
			segment = re.String()
		}
		return false, &InvalidRangeError{
			segment,
			from,
			to,
		}
	}
}
