//go:build gore2regex

package regexp

import (
	re "github.com/wasilibs/go-re2"
)

const Version = "github.com/wasilibs/go-re2"

type Regexp = re.Regexp

func MustCompile(str string) *re.Regexp {
	return re.MustCompile(str)
}
