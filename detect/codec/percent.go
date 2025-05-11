package codec

// decodePercent decodes percent encoded strings consisting of ONLY percent
// encoded characters
func decodePercent(encodedValue string) string {
	size := len(encodedValue)

	// percent encoded values should be multiples of three characters
	if size%3 != 0 {
		return ""
	}

	decodedValue := make([]byte, size/3)
	for i := 0; i < size; i += 3 {
		n1 := encodedValue[i+1]
		n2 := encodedValue[i+2]
		b := byte(hexMap[n1]<<4 | hexMap[n2])

		if !printableASCII[b] {
			return ""
		}

		decodedValue[i/3] = b
	}

	return string(decodedValue)
}
