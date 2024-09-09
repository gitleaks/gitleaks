package config

import (
	"regexp"
	"regexp/syntax"
	"unicode"

	"github.com/rs/zerolog/log"
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

// IsBoundaryBesideNonWord checks if a word boundary (\b) is adjacent to a non-word character in the regex.
func IsBoundaryBesideNonWord(pattern string) (bool, error) {
	// Parse the regex pattern into a syntax tree.
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false, err
	}

	log.Info().Msgf("Checking pattern: %s", pattern)
	// Recursively check if a word boundary is beside a non-word character.
	return checkBoundary(re), nil
}

// CheckBoundary traverses the parsed regex tree and checks for word boundaries adjacent to non-word characters.
func checkBoundary(re *syntax.Regexp) bool {
	log.Debug().Msgf("[checkBoundary] testing, re = %v, sub = %v", re, re.Sub)
	for i, sub := range re.Sub {
		// Check if the current node is a word boundary.
		if sub.Op == syntax.OpWordBoundary {
			var (
				before *syntax.Regexp
				after  *syntax.Regexp
			)
			if i > 0 {
				before = re.Sub[i-1]
				log.Debug().Msgf("[checkBoundary] before = %v (%v)", before, before.Op)
			}
			if i < len(re.Sub)-1 {
				after = re.Sub[i+1]
				log.Debug().Msgf("[checkBoundary] after = %v (%v)", after, after.Op)
			}
			log.Debug().Msgf("[checkBoundary] before = %v, after = %v", before, after)
			// Check if the next or previous node is a non-word character.
			if (i > 0 && isNonWordChar(before, true)) || (i < len(re.Sub)-1 && isNonWordChar(after, false)) {
				log.Debug().Msgf("[checkBoundary] non-word character: before = %v, after = %v", before, after)
				return true
			}
			log.Debug().Msgf("[checkBoundary] word character: before = %v, after = %v", before, after)
		}

		// Recursively check sub-expressions.
		if checkBoundary(sub) {
			return true
		}
	}
	return false
}

// IsNonWordChar checks if the regex node represents a non-word character.
func isNonWordChar(re *syntax.Regexp, before bool) bool {
	if re.Op == syntax.OpRepeat || re.Op == syntax.OpStar || re.Op == syntax.OpPlus {
		re = re.Sub[0]
	}

	switch re.Op {
	case syntax.OpAnyChar:
		return true
	case syntax.OpLiteral: // a
		log.Info().Msgf("[isNonWordChar#literal] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		var r rune
		// Check if the literal contains non-word character (anything not [a-zA-Z0-9_]).
		if before {
			// Check the rune at the end of "before".
			r = re.Rune[len(re.Rune)-1]
		} else {
			// Check the rune at the start of "after".
			r = re.Rune[0]
		}
		if !isWordCharacter(r) {
			log.Debug().Msgf("[isNonWordChar] non-word character: after = %s", string(r))
			return true
		}
	case syntax.OpCharClass: // [a-z0-9]
		log.Info().Msgf("[isNonWordChar#charclass] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		// Check if the character class contains only non-word characters.
		for i := 0; i < len(re.Rune); i += 2 {
			from, to := re.Rune[i], re.Rune[i+1]
			if !isWordCharacterRange(from, to) {
				return true
			}
		}
	case syntax.OpCapture, // (a|b)
		syntax.OpAlternate: // (?:a|b)
		log.Info().Msgf("[isNonWordChar#cap/alt] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		for _, sub := range re.Sub {
			if isNonWordChar(sub, before) {
				return true
			}
		}
	case syntax.OpConcat: // (?:foo)bar
		log.Info().Msgf("[isNonWordChar#con] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)

		var r *syntax.Regexp
		if before {
			r = re.Sub[len(re.Sub)-1]
		} else {
			r = re.Sub[0]
		}

		if r.Op == syntax.OpQuest {
			log.Warn().Msgf("Info quest before! r = %v", r)
			for _, sub := range re.Sub {
				log.Warn().Msgf("[isNonWordChar#concat/before] quest s = %v", sub)
				if isNonWordChar(sub, before) {
					return true
				}
			}
		} else {
			for _, sub := range r.Sub {
				log.Warn().Msgf("[isNonWordChar#concat/before] s = %v", sub)
				if isNonWordChar(sub, before) {
					return true
				}
			}
		}

		if isNonWordChar(r, before) {
			return true
		}
	case syntax.OpQuest: // a?
		log.Info().Msgf("[isNonWordChar#quest] is: op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
		for _, sub := range re.Sub {
			log.Warn().Msgf("[isNonWordChar#quest/sub] op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
			if isNonWordChar(sub, before) {
				return true
			}
		}
	case syntax.OpWordBoundary:
		if checkBoundary(re) {
			return true
		}
	default:
		log.Fatal().Msgf("unhandled: op = %v, re = %v, sub = %v", re.Op, re, re.Sub)
	}
	return false
}

func isWordCharacter(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isWordCharacterRange(from, to rune) bool {
	return isWordCharacter(from) && isWordCharacter(to)
}
