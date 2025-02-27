//go:build stdregex

package regexp

import (
	re "regexp"
)

const Version = "stdlib"

type Regexp = re.Regexp

func MustCompile(str string) *re.Regexp {
	return re.MustCompile(str)
}
