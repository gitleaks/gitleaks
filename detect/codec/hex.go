package codec

// hexMap is a precalculated map of hex nibbles
var hexMap [128]int

// likelyHexChars is a set of characters that you would expect to find at
// least one of in hex encoded data. This risks missing some hex data that
// doesn't contain these characters, but gives you the performance gain of not
// trying to decode a lot of long symbols in code.
var likelyHexChars = make([]bool, 256)

func init() {
	for i, c := range `0123456789abcdef` {
		hexMap[c] = i
	}
	for i, c := range `ABCDEF` {
		hexMap[c] = i + 10
	}
	for _, c := range `0123456789` {
		likelyHexChars[c] = true
	}
}

// decodeHex decodes hex data
func decodeHex(encodedValue string) string {
	size := len(encodedValue)
	// hex should have two characters per byte
	if size%2 != 0 {
		return ""
	}
	if !hasByte(encodedValue, likelyHexChars) {
		return ""
	}

	decodedValue := make([]byte, size/2)
	for i := 0; i < size; i += 2 {
		n1 := encodedValue[i]
		n2 := encodedValue[i+1]
		b := byte(hexMap[n1]<<4 | hexMap[n2])

		if !printableASCII[b] {
			return ""
		}

		decodedValue[i/2] = b
	}

	return string(decodedValue)
}
