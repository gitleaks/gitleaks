// == WARNING ==
// These functions are used to generate GitLeak's default config.
// You are free to use these in your own project, HOWEVER, no API stability is guaranteed.

package utils

import (
	"fmt"
)

func Numeric(size string) string {
	return fmt.Sprintf(`[0-9]{%s}`, size)
}

func Hex(size string) string {
	return fmt.Sprintf(`[a-f0-9]{%s}`, size)
}

func AlphaNumeric(size string) string {
	return fmt.Sprintf(`[a-z0-9]{%s}`, size)
}

func AlphaNumericExtendedShort(size string) string {
	return fmt.Sprintf(`[a-z0-9_-]{%s}`, size)
}

func AlphaNumericExtended(size string) string {
	return fmt.Sprintf(`[a-z0-9=_\-]{%s}`, size)
}

func AlphaNumericExtendedLong(size string) string {
	return fmt.Sprintf(`[a-z0-9\/=_\+\-]{%s}`, size)
}

func Hex8_4_4_4_12() string {
	return `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
}
