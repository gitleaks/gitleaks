package codec

var printableASCII [256]bool

func init() {
	for b := 0; b < len(printableASCII); b++ {
		if '\x08' < b && b < '\x7f' {
			printableASCII[b] = true
		}
	}
}

// isPrintableASCII returns true if all bytes are printable ASCII
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if !printableASCII[c] {
			return false
		}
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
