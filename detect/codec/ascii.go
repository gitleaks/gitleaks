package codec

import "unicode/utf8"

var printableASCII [256]bool

func init() {
	for b := 0; b < len(printableASCII); b++ {
		if '\x08' < b && b < '\x7f' {
			printableASCII[b] = true
		}
	}
}

// isPrintableASCII returns true if all bytes are printable ASCII or valid UTF-8
func isPrintableASCII(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		// Check for printable ASCII (single byte)
		if printableASCII[c] {
			i++
			continue
		}
		// Check for valid UTF-8 multi-byte sequence
		if c >= 0x80 {
			r, size := utf8.DecodeRune(b[i:])
			if r != utf8.RuneError && size > 1 {
				i += size
				continue
			}
		}
		return false
	}

	return true
}

// hasByte can be used to check if a string has at least one of the provided
// bytes. Note: make sure byteset is long enough to handle the largest byte in
// the string.
func hasByte(data string, byteset []bool) bool {
	for i := 0; i < len(data); i++ {
		if byteset[data[i]] {
			return true
		}
	}
	return false
}
