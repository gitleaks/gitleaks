package config

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"strconv"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"golang.org/x/exp/maps"

	"github.com/zricethezav/gitleaks/v8/config/flags"
	"github.com/zricethezav/gitleaks/v8/logging"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

type AllowlistMatchCondition int

const (
	AllowlistMatchOr AllowlistMatchCondition = iota
	AllowlistMatchAnd
)

func (a AllowlistMatchCondition) String() string {
	return [...]string{
		"OR",
		"AND",
	}[a]
}

// Allowlist allows a rule to be ignored for specific
// regexes, paths, and/or commits
type Allowlist struct {
	// Short human readable description of the allowlist.
	Description string

	// MatchCondition determines whether all criteria must match.
	MatchCondition AllowlistMatchCondition

	// Commits is a slice of commit SHAs that are allowed to be ignored. Defaults to "OR".
	Commits []string

	// Paths is a slice of path regular expressions that are allowed to be ignored.
	Paths []*regexp.Regexp

	// Can be `match` or `line`.
	//
	// If `match` the _Regexes_ will be tested against the match of the _Rule.Regex_.
	//
	// If `line` the _Regexes_ will be tested against the entire line.
	//
	// If RegexTarget is empty, it will be tested against the found secret.
	RegexTarget string

	// Regexes is slice of content regular expressions that are allowed to be ignored.
	Regexes []*regexp.Regexp

	// StopWords is a slice of stop words that are allowed to be ignored.
	// This targets the _secret_, not the content of the regex match like the
	// Regexes slice.
	StopWords []string

	Expression string

	// validated is an internal flag to track whether `Validate()` has been called.
	validated     bool
	celExpression cel.Program
}

var (
	expressionOnce sync.Once
	useExpression  bool

	// TODO: Double-check if it's safe to reuse this across multiple expressions.
	celEnv = sync.OnceValues(func() (*cel.Env, error) {
		return cel.NewEnv(
			// General fields.
			cel.Variable("ruleId", cel.StringType),
			cel.Variable("keywords", cel.ListType(cel.StringType)),
			cel.Variable("file", cel.StringType),
			cel.Variable("line", cel.StringType),
			cel.Variable("match", cel.StringType),
			cel.Variable("secret", cel.StringType),
			cel.Variable("entropy", cel.DoubleType),
			// Git-specific fields.
			cel.Variable("commit", cel.StringType),
			cel.Variable("author", cel.StringType),
			cel.Variable("email", cel.StringType),
			cel.Variable("date", cel.TimestampType),
			cel.Variable("message", cel.StringType),
			// Functions
			ext.Strings(),
			cel.Function("md5", // https://en.wikipedia.org/wiki/MD5
				cel.Overload("md5_string",
					[]*cel.Type{cel.StringType},
					cel.StringType,
					cel.UnaryBinding(func(val ref.Val) ref.Val {
						s, ok := val.Value().(string)
						if !ok {
							return types.NewErr("invalid input to md5: expected string")
						}
						sum := md5.Sum([]byte(s))
						return types.String(hex.EncodeToString(sum[:]))
					}),
				),
			),
			cel.Function("crc32", // https://wiki.osdev.org/CRC32#:~:text=4.1%20External%20Links-,The%20Basic%20Algorithm,is%20the%20final%20CRC32%20result.
				cel.Overload("crc32_string",
					[]*cel.Type{cel.StringType},
					cel.StringType,
					cel.UnaryBinding(func(val ref.Val) ref.Val {
						s, ok := val.Value().(string)
						if !ok {
							return types.NewErr("invalid input to crc32: expected string")
						}
						sum := crc32.ChecksumIEEE([]byte(s))
						return types.String(fmt.Sprintf("%08x", sum))
					}),
				),
			),
			cel.Function("base62encode",
				cel.Overload("base62encode_string",
					[]*cel.Type{cel.StringType},
					cel.StringType,
					cel.UnaryBinding(func(val ref.Val) ref.Val {
						s, ok := val.Value().(string)
						if !ok {
							return types.NewErr("invalid input to base62encode: expected string")
						}

						// Parse hex string to uint32
						value, err := strconv.ParseUint(s, 16, 32)
						if err != nil {
							return types.NewErr("invalid hex string: %v", err)
						}

						// Convert to Base62 with 6-character padding
						return types.String(EncodeBase62(uint32(value), 6))
					}),
				),
			),
		)
	})
)

func (a *Allowlist) Validate() error {
	if a.validated {
		return nil
	}
	expressionOnce.Do(func() {
		useExpression = flags.EnableExperimentalAllowlistExpression.Load()
	})

	// Disallow empty allowlists.
	if len(a.Commits) == 0 &&
		len(a.Paths) == 0 &&
		len(a.Regexes) == 0 &&
		len(a.StopWords) == 0 && a.Expression == "" {
		return errors.New("must contain at least one check for: commits, paths, regexes, or stopwords")
	}

	// Deduplicate commits and stopwords.
	if len(a.Commits) > 0 {
		uniqueCommits := make(map[string]struct{})
		for _, commit := range a.Commits {
			uniqueCommits[commit] = struct{}{}
		}
		a.Commits = maps.Keys(uniqueCommits)
	}
	if len(a.StopWords) > 0 {
		uniqueStopwords := make(map[string]struct{})
		for _, stopWord := range a.StopWords {
			uniqueStopwords[stopWord] = struct{}{}
		}
		a.StopWords = maps.Keys(uniqueStopwords)
	}

	// Compile the expression
	if useExpression && a.Expression != "" {
		// Build the environment: variables and functions available to the users.
		env, err := celEnv()
		if err != nil {
			return fmt.Errorf("failed to initialize CEL environment: %w", err)
		}

		// Parse the user-provided expression. (For some reason `Compile` and `Check` are two steps.)
		ast, issues := env.Compile(a.Expression)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("failed to compile expression: %w", issues.Err())
		}
		checked, issues := env.Check(ast)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("failed to compile expression: %w", issues.Err())
		}

		if checked.OutputType() != cel.BoolType {
			return fmt.Errorf("invalid expression: return type must be bool, not %s", checked.OutputType().String())
		}
		prg, err := env.Program(checked)
		if err != nil {
			return fmt.Errorf("failed to build expression: %w", err)
		}
		a.celExpression = prg
	}

	a.validated = true
	return nil
}

// CommitAllowed returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) (bool, string) {
	if a == nil || c == "" {
		return false, ""
	}

	for _, commit := range a.Commits {
		if commit == c {
			return true, c
		}
	}
	return false, ""
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	if a == nil || path == "" {
		return false
	}
	return anyRegexMatch(path, a.Paths)
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(secret string) bool {
	if a == nil || secret == "" {
		return false
	}
	return anyRegexMatch(secret, a.Regexes)
}

func (a *Allowlist) ContainsStopWord(s string) (bool, string) {
	if a == nil || s == "" {
		return false, ""
	}

	s = strings.ToLower(s)
	for _, stopWord := range a.StopWords {
		if strings.Contains(s, strings.ToLower(stopWord)) {
			return true, stopWord
		}
	}
	return false, ""
}

// ExpressionAllowed returns the result of the predicate expression.
func (a *Allowlist) ExpressionAllowed(
// Miserable workaround to import-cycles.
	ruleId string,
	keywords []string,
	file string,
	line string,
	match string,
	secret string,
	entropy float32,
	commit string,
	author string,
	email string,
	date string,
	message string,
) bool {
	if a == nil || a.celExpression == nil {
		return false
	}

	out, _, err := a.celExpression.Eval(map[string]any{
		// General
		"ruleId":   ruleId,
		"keywords": keywords,
		"file":     file,
		"line":     line,
		"match":    match,
		"secret":   secret,
		"entropy":  entropy,
		// Git
		"commit":  commit,
		"author":  author,
		"email":   email,
		"date":    date,
		"message": message,
	})
	if err != nil {
		logging.Err(err).Msg("Failed to evaluate allowlist expression")
		return false
	}
	return out.Value().(bool)
}
