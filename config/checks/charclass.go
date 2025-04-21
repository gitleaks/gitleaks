package checks

import (
	"fmt"
	"regexp/syntax"
)

type InvalidRangeError struct {
	Segment string
	From    rune
	To      rune
}

func (e *InvalidRangeError) Error() string {
	return fmt.Sprintf("invalid character range: [%q, %q] in `%s`", e.From, e.To, e.Segment)
}

func checkCharClass(pat string, re *syntax.Regexp) *InvalidRangeError {
	//logging.Info().Msgf("[1] checking: op = %v, re = %v", re.Op, re)

	if re.Op == syntax.OpCharClass {
		// Check if the character class contains only non-word characters.
		for i := 0; i < len(re.Rune); i += 2 {
			from, to := re.Rune[i], re.Rune[i+1]
			// Ignore negative ranges ([^\t\s ]).
			if i == 0 && from == 0x00 {
				break
			}
			//logging.Info().Msgf("[2] checking charClass: re = %v, from=%q, to=%q", re, from, to)
			// Single character
			if from == to {
				continue
			}
			if err := _isWordCharacterRange(re, from, to); err != nil {
				return err
			}
		}
	}

	for _, sub := range re.Sub {
		switch sub.Op {
		case syntax.OpLiteral:
			continue
		default:
			return checkCharClass(pat, sub)
		}
	}
	return nil
}

func _isWordCharacterRange(re *syntax.Regexp, from rune, to rune) *InvalidRangeError {
	switch {
	case (from >= '0' && from < '9') && (to > '0' && to <= '9'):
		return nil
	case (from >= 'A' && from < 'Z') && (to > 'A' && to <= 'Z'):
		return nil
	case (from >= 'a' && from < 'z') && (to > 'a' && to <= 'z'):
		return nil
	default:
		var segment string
		if re != nil {
			segment = re.String()
		}
		return &InvalidRangeError{
			segment,
			from,
			to,
		}
	}
}
