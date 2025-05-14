package codec

import (
	"encoding/base64"
)

// likelyBase64Chars is a set of characters that you would expect to find at
// least one of in base64 encoded data. This risks missing about 1% of
// base64 encoded data that doesn't contain these characters, but gives you
// the performance gain of not trying to decode a lot of long symbols in code.
var likelyBase64Chars = make([]bool, 256)

func init() {
	for _, c := range `0123456789+/-_` {
		likelyBase64Chars[c] = true
	}
}

// decodeBase64 decodes base64 encoded printable ASCII characters
func decodeBase64(encodedValue string) string {
	// Exit early if it doesn't seem like base64
	if !hasByte(encodedValue, likelyBase64Chars) {
		return ""
	}

	// Try standard base64 decoding
	decodedValue, err := base64.StdEncoding.DecodeString(encodedValue)
	if err == nil && isPrintableASCII(decodedValue) {
		return string(decodedValue)
	}

	// Try base64url decoding
	decodedValue, err = base64.RawURLEncoding.DecodeString(encodedValue)
	if err == nil && isPrintableASCII(decodedValue) {
		return string(decodedValue)
	}

	return ""
}
